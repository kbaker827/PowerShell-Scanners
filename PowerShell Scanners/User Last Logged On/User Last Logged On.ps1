# This script requires that Audit Logon events are enabled in Group Policy and those events are kept for the amount of history preferred

[CmdletBinding()]
param (
    [Switch]$Lowercase
)

$Results = New-Object System.Collections.ArrayList
$UserArray = New-Object System.Collections.ArrayList

# Query all logon events with id 4624
Get-EventLog -LogName "Security" -newest 200 -InstanceId 4624 -ErrorAction "SilentlyContinue" | ForEach-Object {

    $EventMessage = $_
    $AccountName = $EventMessage.ReplacementStrings[5]
    $LogonType = $EventMessage.ReplacementStrings[8]

    if ( $Lowercase ) {

        # Make all usernames lowercase so they group properly in Inventory
        $AccountName = $AccountName.ToLower()

    }

    # Look for events that contain local or remote logon events, while ignoring Windows service accounts
    if ( ( $LogonType -in "2", "10", "11" ) -and ( $AccountName -notmatch "^(DWM|UMFD)-\d" -and ($AccountName -ne "") ) ) {

        # Skip duplicate names
        if ( $UserArray -notcontains $AccountName ) {

            $null = $UserArray.Add($AccountName)

            # Translate the Logon Type
            if ( $LogonType -eq "2" ) {

                $LogonTypeName = "Local"

            } elseif ( $LogonType -eq "10" ) {

                $LogonTypeName = "Remote"

            } elseif ( $LogonType -eq "11" ) {

                $LogonTypeName = "Cached"
            }

            # Build an object containing the Username, Logon Type, and Last Logon time
            $null = $Results.Add([PSCustomObject]@{
                Username  = $AccountName
                LogonType = $LogonTypeName
                LastLogon = [DateTime]$EventMessage.TimeGenerated.ToString("yyyy-MM-dd HH:mm:ss")
            })

        }

    }

}

# Fall back to quser to catch currently logged-on users that have no matching security event
# (common on machines where only logon types 3/5 are present, e.g. remote-only or VDI sessions)
try {
    $queryUser = quser 2>&1
}
catch {
    $Results
    return
}

if ( $LASTEXITCODE -ne 0 ) {

    $Results
    return

}

$userName = $null
if ( $queryUser ) {

    if ( $queryUser -match '\s(\S+)\s+\d+\s' ) {
        $userName = $matches[1]
    }

}

if ( $null -eq $userName ) {

    $Results
    return

}

if ( $Lowercase ) {
    $userName = $userName.ToLower()
}

if ( $UserArray -notcontains $userName ) {

    $null = $Results.Add([PSCustomObject]@{
        Username  = $userName
        LogonType = "Current User"
        LastLogon = [DateTime](Get-Date)
    })

}

$Results
