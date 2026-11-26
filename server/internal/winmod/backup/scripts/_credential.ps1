function New-EasyRmmCredential([string]$User, [string]$Secret) {
    $secure = ConvertTo-SecureString -String $Secret -AsPlainText -Force
    return New-Object System.Management.Automation.PSCredential($User, $secure)
}
