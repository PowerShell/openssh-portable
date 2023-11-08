$data = "temp pipe data"
write-host "Length of `$data: " $data.Length;
$npipeServer = new-object System.IO.Pipes.NamedPipeServerStream[] 4;
for ($i = 0; $i -lt $npipeServer.Length; $i++)
{
    $npipeServer[$i] = new-object System.IO.Pipes.NamedPipeServerStream('npipe',
                              [System.IO.Pipes.PipeDirection]::Out,
                              [System.IO.Pipes.NamedPipeServerStream]::MaxAllowedServerInstances,
                              [System.IO.Pipes.PipeTransmissionMode]::Byte,
                              [System.IO.Pipes.PipeOptions]::Asynchronous,
                              1,
                              1);
    $npipeServer[$i].WaitForConnectionAsync();
}
for ( ; ; )
{
    $complete = $false;
    for ($i = 0; $i -lt $npipeServer.Length; $i++)
    {
        if ($npipeServer[$i].IsConnected -eq $true)
        {
            try 
            {
                for ($x = 0; $x -lt $data.Length; $x++)
                {
                    $npipeServer[$i].WriteByte($data[$x]);
                }
                $npipeServer[$i].WaitForPipeDrain();
            }
            catch [System.IO.IOException]
            {
                write-host "Caught IOException:" $_
            }
            finally
            {
                write-host $x "bytes written."
            }
            $npipeServer[$i].Disconnect();
            $npipeServer[$i].WaitForConnectionAsync();
            if ($x -eq $data.Length) 
            {
                $complete = $true;
                break;
            }
        }
        if ($complete -eq $true) 
        {
            break;
        }
    }
    if ($complete -eq $true) 
    {
        break;
    }
}
for ($i = 0; $i -lt $npipeServer.Length; $i++)
{
    if ($npipeServer[$i].IsConnected -eq $true)
    {
        $npipeServer[$i].Disconnect();
    }
    $npipeServer[$i].Close();
}
