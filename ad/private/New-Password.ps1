<#
.SYNOPSIS
Generates a cryptographically secure, complex password string.

.DESCRIPTION
New-Password produces strong random passwords using a cryptographically secure RNG.
It guarantees inclusion of lowercase, uppercase, numeric, and symbol characters.
Supports custom symbols, optional ambiguous characters, and can return entropy metadata.

.PARAMETER Length
Password length (minimum 24; default 24).

.PARAMETER IncludeAmbiguous
Include ambiguous characters (e.g., l, I, O, 0).

.PARAMETER CustomSymbols
Override the default symbol set with a custom string.

.PARAMETER ReturnMetadata
Return password with length and entropy info as an object.

.EXAMPLE
# Generate a 32-character password
New-Password -Length 32

.EXAMPLE
# Generate a password and return metadata
New-Password -Length 32 -ReturnMetadata

.OUTPUTS
[string] (default) or [PSCustomObject] when -ReturnMetadata is used.

.NOTES
Author: NightCityShogun  
Version: 1.0  
Requires: .NET RandomNumberGenerator (cryptographically secure).  
Behavior: Ensures minimum complexity, shuffles all characters, and calculates entropy bits.  
Security: Avoid storing plaintext output; handle immediately or convert to SecureString.  
© 2025 NightCityShogun. All rights reserved.
#>


function New-Password {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateRange(24, [int]::MaxValue)]
        [int]$Length = 24,
        [Parameter(Mandatory = $false)]
        [switch]$IncludeAmbiguous,
        [Parameter(Mandatory = $false)]
        [string]$CustomSymbols,
        [Parameter(Mandatory = $false)]
        [switch]$ReturnMetadata
    )
    try {
        # Validate Length
        if ($Length -lt 24) {
            throw "Password length must be at least 24 characters."
        }
        # Define Character Classes
        $lowercase = if ($IncludeAmbiguous) { 'abcdefghijklmnopqrstuvwxyz' } else { 'abcdefghijkmnopqrstuvwxyz' }
        $uppercase = if ($IncludeAmbiguous) { 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' } else { 'ABCDEFGHJKLMNOPQRSTUVWXYZ' }
        $numbers = '0123456789'
        $symbols = if ($CustomSymbols) { $CustomSymbols } else { '@#$%^&*-_=+[]{}|:,?.!/`~";()<>''' }
        $allChars = $lowercase + $uppercase + $numbers + $symbols
        # Use Cryptographically Secure Random Number Generator
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        # Helper Function to Get Random Character
        function Get-RandomChar {
            param ([string]$CharSet)
            $bytes = [byte[]]::new(4)
            $rng.GetBytes($bytes)
            $index = [BitConverter]::ToUInt32($bytes, 0) % $CharSet.Length
            return $CharSet[$index]
        }
        # Ensure Minimum Complexity
        $mandatory = @(
            (Get-RandomChar -CharSet $lowercase),
            (Get-RandomChar -CharSet $uppercase),
            (Get-RandomChar -CharSet $numbers),
            (Get-RandomChar -CharSet $symbols)
        )
        # Generate Remaining Characters
        $remainingLength = $Length - $mandatory.Count
        $remaining = for ($i = 0; $i -lt $remainingLength; $i++) {
            Get-RandomChar -CharSet $allChars
        }
        # Combine and Shuffle
        $allCharsArray = $mandatory + $remaining
        $shuffled = for ($i = $allCharsArray.Count - 1; $i -gt 0; $i--) {
            $bytes = [byte[]]::new(4)
            $rng.GetBytes($bytes)
            $j = [BitConverter]::ToUInt32($bytes, 0) % ($i + 1)
            $allCharsArray[$i], $allCharsArray[$j] = $allCharsArray[$j], $allCharsArray[$i]
        }
        $passwordString = -join $allCharsArray
        # Calculate Entropy (simplified, for reference)
        $charSetSize = $allChars.Length
        $entropy = [math]::Log([math]::Pow($charSetSize, $Length), 2)
        # Return Password (string by default, or object if ReturnMetadata is specified)
        if ($ReturnMetadata) {
            return [PSCustomObject]@{
                Password = $passwordString
                Length = $Length
                Entropy = [math]::Round($entropy, 2)
            }
        }
        return $passwordString
    }
    catch {
        Write-Error "Error generating password: $($_.Exception.Message)"
        return $null
    }
    finally {
        if ($rng) { $rng.Dispose() }
    }

}
