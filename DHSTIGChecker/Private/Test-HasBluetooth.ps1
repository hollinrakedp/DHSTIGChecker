function Test-HasBluetooth {
    param ()
    
    begin {}
    
    process {
        $BluetoothNetwork = Get-CimInstance Win32_NetworkProtocol -Filter 'Name like "%Bluetooth%"' -Verbose:$false
        $BluetoothDevice = Get-PnpDevice |Where-Object {$_.Name -like "*Bluetooth*"}
        if ($BluetoothNetwork -or $BluetoothDevice) {
            $true
        }
        else {
            $false
        }
    }
    
    end {}
}
