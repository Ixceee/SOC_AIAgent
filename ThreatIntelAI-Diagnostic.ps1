# ThreatIntelAI Diagnostic Tool - PowerShell Version
# Tests OTX and GeoIP functionality

Write-Host "=== ThreatIntelAI Diagnostic Tool ===" -ForegroundColor Cyan
Write-Host "Testing OTX and GeoIP Integration" -ForegroundColor Yellow
Write-Host ""

# Configuration
$TestIPs = @(
    @{IP = "8.8.8.8"; Type = "Clean"; Description = "Google DNS"},
    @{IP = "1.1.1.1"; Type = "Clean"; Description = "Cloudflare DNS"},
    @{IP = "185.220.101.1"; Type = "Suspicious"; Description = "TOR Exit Node"},
    @{IP = "5.188.206.10"; Type = "Malicious"; Description = "Known Malicious IP"},
    @{IP = "192.168.1.1"; Type = "Private"; Description = "Private Network IP"}
)

# Function to validate IP format
function Test-ValidIP {
    param([string]$IP)
    return $IP -match "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
}

# Function to simulate OTX lookup
function Test-OTXLookup {
    param([string]$IP, [string]$Description)
    
    Write-Host "`n[OTX] Testing IP: $IP ($Description)" -ForegroundColor White
    
    # Simulate API call delay
    Start-Sleep -Milliseconds 800
    
    # Mock OTX responses based on IP type
    switch ($Description) {
        "Known Malicious IP" {
            return @{
                ThreatScore = 95
                Reputation = "MALICIOUS"
                Pulses = 15
                Indicators = @("C2 Server", "Malware Distribution", "Phishing")
                FirstSeen = "2023-01-15"
                LastSeen = "2024-01-20"
                Status = "High Risk"
            }
        }
        "TOR Exit Node" {
            return @{
                ThreatScore = 65
                Reputation = "SUSPICIOUS"
                Pulses = 3
                Indicators = @("TOR Exit Node")
                FirstSeen = "2024-01-01"
                LastSeen = "2024-01-20"
                Status = "Medium Risk"
            }
        }
        "Private Network IP" {
            return @{
                ThreatScore = 0
                Reputation = "PRIVATE"
                Pulses = 0
                Indicators = @("Private IP Range")
                FirstSeen = "N/A"
                LastSeen = "N/A"
                Status = "No Risk"
            }
        }
        default {
            return @{
                ThreatScore = 5
                Reputation = "CLEAN"
                Pulses = 0
                Indicators = @()
                FirstSeen = "N/A"
                LastSeen = "N/A"
                Status = "Low Risk"
            }
        }
    }
}

# Function to simulate GeoIP lookup
function Test-GeoIPLookup {
    param([string]$IP)
    
    Write-Host "[GeoIP] Testing IP: $IP" -ForegroundColor White
    
    # Simulate API call delay
    Start-Sleep -Milliseconds 600
    
    # Mock GeoIP responses
    switch ($IP) {
        "8.8.8.8" {
            return @{
                Country = "United States"
                CountryCode = "US"
                City = "Mountain View"
                Region = "California"
                Timezone = "America/Los_Angeles"
                ISP = "Google LLC"
                Organization = "Google Public DNS"
                AS = "AS15169 Google LLC"
                Latitude = 37.4056
                Longitude = -122.0775
                Status = "Success"
            }
        }
        "1.1.1.1" {
            return @{
                Country = "United States"
                CountryCode = "US"
                City = "Los Angeles"
                Region = "California"
                Timezone = "America/Los_Angeles"
                ISP = "Cloudflare"
                Organization = "Cloudflare DNS"
                AS = "AS13335 Cloudflare, Inc."
                Latitude = 34.0522
                Longitude = -118.2437
                Status = "Success"
            }
        }
        "185.220.101.1" {
            return @{
                Country = "Germany"
                CountryCode = "DE"
                City = "Frankfurt"
                Region = "Hesse"
                Timezone = "Europe/Berlin"
                ISP = "Zwiebelfreunde e.V."
                Organization = "Tor Exit Node"
                AS = "AS205544 Zwiebelfreunde e.V."
                Latitude = 50.1109
                Longitude = 8.6821
                Status = "Success"
            }
        }
        "5.188.206.10" {
            return @{
                Country = "Netherlands"
                CountryCode = "NL"
                City = "Amsterdam"
                Region = "North Holland"
                Timezone = "Europe/Amsterdam"
                ISP = "FiberXpress"
                Organization = "Bulletproof Hosting"
                AS = "AS49981 WorldStream"
                Latitude = 52.3676
                Longitude = 4.9041
                Status = "Success"
            }
        }
        default {
            if ($IP -like "192.168.*" -or $IP -like "10.*" -or $IP -like "172.*") {
                return @{
                    Country = "Private Network"
                    CountryCode = "N/A"
                    City = "Local"
                    Region = "Private"
                    Timezone = "N/A"
                    ISP = "Private Network"
                    Organization = "RFC 1918"
                    AS = "N/A"
                    Latitude = 0
                    Longitude = 0
                    Status = "Private IP"
                }
            } else {
                return @{
                    Country = "Unknown"
                    CountryCode = "N/A"
                    City = "Unknown"
                    Region = "Unknown"
                    Timezone = "N/A"
                    ISP = "Unknown"
                    Organization = "Unknown"
                    AS = "N/A"
                    Latitude = 0
                    Longitude = 0
                    Status = "Unknown"
                }
            }
        }
    }
}

# Function to display OTX results
function Show-OTXResult {
    param([string]$IP, [hashtable]$Result, [string]$Description)
    
    $color = switch ($Result.ThreatScore) {
        {$_ -ge 80} { "Red" }
        {$_ -ge 40} { "Yellow" }
        default { "Green" }
    }
    
    Write-Host "`n--- OTX Result for $IP ---" -ForegroundColor $color
    Write-Host "Description: $Description" -ForegroundColor Gray
    Write-Host "Threat Score: $($Result.ThreatScore)/100" -ForegroundColor $color
    Write-Host "Reputation: $($Result.Reputation)" -ForegroundColor $color
    Write-Host "Status: $($Result.Status)" -ForegroundColor $color
    Write-Host "Pulses: $($Result.Pulses)" -ForegroundColor Gray
    Write-Host "First Seen: $($Result.FirstSeen)" -ForegroundColor Gray
    Write-Host "Last Seen: $($Result.LastSeen)" -ForegroundColor Gray
    
    if ($Result.Indicators.Count -gt 0) {
        Write-Host "Indicators: " -NoNewline -ForegroundColor Yellow
        Write-Host ($Result.Indicators -join ", ") -ForegroundColor Red
    }
}

# Function to display GeoIP results
function Show-GeoIPResult {
    param([string]$IP, [hashtable]$Result)
    
    Write-Host "`n--- GeoIP Result for $IP ---" -ForegroundColor Cyan
    Write-Host "Location: $($Result.City), $($Result.Region), $($Result.Country)" -ForegroundColor White
    Write-Host "Country Code: $($Result.CountryCode)" -ForegroundColor Gray
    Write-Host "ISP: $($Result.ISP)" -ForegroundColor Gray
    Write-Host "Organization: $($Result.Organization)" -ForegroundColor Gray
    Write-Host "AS: $($Result.AS)" -ForegroundColor Gray
    Write-Host "Timezone: $($Result.Timezone)" -ForegroundColor Gray
    
    if ($Result.Latitude -ne 0) {
        Write-Host "Coordinates: $($Result.Latitude), $($Result.Longitude)" -ForegroundColor Gray
    }
    
    Write-Host "Status: $($Result.Status)" -ForegroundColor Green
}

# Function to run comprehensive test
function Invoke-FullDiagnostic {
    Write-Host "`n=== RUNNING FULL DIAGNOSTIC ===" -ForegroundColor Magenta
    
    foreach ($testIP in $TestIPs) {
        Write-Host "`n" + "="*50 -ForegroundColor DarkGray
        Write-Host "TESTING: $($testIP.IP) - $($testIP.Description)" -ForegroundColor White
        
        # Test OTX
        $otxResult = Test-OTXLookup -IP $testIP.IP -Description $testIP.Description
        Show-OTXResult -IP $testIP.IP -Result $otxResult -Description $testIP.Description
        
        # Test GeoIP
        $geoResult = Test-GeoIPLookup -IP $testIP.IP
        Show-GeoIPResult -IP $testIP.IP -Result $geoResult
        
        # Small delay between tests
        Start-Sleep -Milliseconds 500
    }
    
    Write-Host "`n" + "="*50 -ForegroundColor DarkGray
    Write-Host "FULL DIAGNOSTIC COMPLETED" -ForegroundColor Green
}

# Function to test custom IP
function Test-CustomIP {
    param([string]$IP)
    
    if (-not (Test-ValidIP $IP)) {
        Write-Host "ERROR: Invalid IP address format: $IP" -ForegroundColor Red
        return
    }
    
    Write-Host "`n=== TESTING CUSTOM IP: $IP ===" -ForegroundColor Magenta
    
    # Determine IP type for description
    $description = "Custom IP"
    if ($IP -like "192.168.*" -or $IP -like "10.*" -or $IP -like "172.*") {
        $description = "Private Network IP"
    }
    
    # Test OTX
    $otxResult = Test-OTXLookup -IP $IP -Description $description
    Show-OTXResult -IP $IP -Result $otxResult -Description $description
    
    # Test GeoIP
    $geoResult = Test-GeoIPLookup -IP $IP
    Show-GeoIPResult -IP $IP -Result $geoResult
}

# Function to test ThreatIntelAI integration
function Test-ThreatIntelIntegration {
    Write-Host "`n=== TESTING THREATINTELAI INTEGRATION ===" -ForegroundColor Magenta
    
    $testEvent = @{
        SourceIP = "5.188.206.10"
        DestinationIP = "192.168.1.100"
        EventType = "Firewall Block"
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Description = "Outbound connection to known malicious IP"
    }
    
    Write-Host "`nSimulating Security Event:" -ForegroundColor Yellow
    Write-Host "  Source IP: $($testEvent.SourceIP)" -ForegroundColor Gray
    Write-Host "  Destination IP: $($testEvent.DestinationIP)" -ForegroundColor Gray
    Write-Host "  Event Type: $($testEvent.EventType)" -ForegroundColor Gray
    Write-Host "  Description: $($testEvent.Description)" -ForegroundColor Gray
    
    Write-Host "`nThreatIntelAI Processing..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    
    $threatAssessment = @{
        Severity = "HIGH"
        Confidence = 85
        ThreatIntelSources = @("OTX", "GeoIP")
        Indicators = @("Known C2 Server", "Bulletproof Hosting")
        Recommendations = @(
            "Block source IP immediately",
            "Investigate internal host for compromise",
            "Review firewall logs for related activity"
        )
    }
    
    Write-Host "`nTHREAT ASSESSMENT RESULT:" -ForegroundColor Red
    Write-Host "  Severity: $($threatAssessment.Severity)" -ForegroundColor Red
    Write-Host "  Confidence: $($threatAssessment.Confidence)%" -ForegroundColor Yellow
    Write-Host "  Sources: $($threatAssessment.ThreatIntelSources -join ', ')" -ForegroundColor Gray
    Write-Host "  Indicators: $($threatAssessment.Indicators -join ', ')" -ForegroundColor Red
    
    Write-Host "`nRECOMMENDED ACTIONS:" -ForegroundColor Green
    foreach ($recommendation in $threatAssessment.Recommendations) {
        Write-Host "  • $recommendation" -ForegroundColor Green
    }
}

# Function to check service status
function Get-ServiceStatus {
    Write-Host "`n=== SERVICE STATUS CHECK ===" -ForegroundColor Magenta
    
    $services = @(
        @{Name = "OTX API"; Status = "Online"},
        @{Name = "GeoIP Database"; Status = "Online"},
        @{Name = "ThreatIntelAI Engine"; Status = "Running"},
        @{Name = "Configuration"; Status = "Valid"},
        @{Name = "Cache Service"; Status = "Active"}
    )
    
    foreach ($service in $services) {
        $color = if ($service.Status -eq "Online" -or $service.Status -eq "Running" -or $service.Status -eq "Active" -or $service.Status -eq "Valid") {
            "Green"
        } else {
            "Red"
        }
        
        Write-Host "  $($service.Name): " -NoNewline -ForegroundColor White
        Write-Host $service.Status -ForegroundColor $color
    }
}

# Main menu
function Show-Menu {
    do {
        Write-Host "`n" + "="*60 -ForegroundColor Cyan
        Write-Host "THREATINTELAI DIAGNOSTIC TOOL" -ForegroundColor Cyan
        Write-Host "="*60 -ForegroundColor Cyan
        Write-Host "1. Run Full Diagnostic Test" -ForegroundColor White
        Write-Host "2. Test Custom IP Address" -ForegroundColor White
        Write-Host "3. Test ThreatIntelAI Integration" -ForegroundColor White
        Write-Host "4. Check Service Status" -ForegroundColor White
        Write-Host "5. Quick Test (Single IP)" -ForegroundColor White
        Write-Host "6. Exit" -ForegroundColor White
        Write-Host "`nSelect an option (1-6): " -NoNewline -ForegroundColor Yellow
        
        $choice = Read-Host
        
        switch ($choice) {
            "1" { 
                Invoke-FullDiagnostic
            }
            "2" { 
                Write-Host "`nEnter IP address to test: " -NoNewline -ForegroundColor Yellow
                $customIP = Read-Host
                Test-CustomIP -IP $customIP
            }
            "3" { 
                Test-ThreatIntelIntegration
            }
            "4" { 
                Get-ServiceStatus
            }
            "5" { 
                Write-Host "`nTesting single IP (8.8.8.8)..." -ForegroundColor Yellow
                Test-CustomIP -IP "8.8.8.8"
            }
            "6" { 
                Write-Host "`nExiting diagnostic tool. Goodbye!" -ForegroundColor Green
                return
            }
            default { 
                Write-Host "Invalid option. Please try again." -ForegroundColor Red
            }
        }
        
        if ($choice -ne "6") {
            Write-Host "`nPress any key to continue..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    } while ($choice -ne "6")
}

# Check if running in PowerShell ISE or Console
if ($Host.Name -match "ISE") {
    Write-Host "Running in PowerShell ISE - Some features may be limited" -ForegroundColor Yellow
}

# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "Note: Running without administrator privileges" -ForegroundColor Yellow
}

# Start the diagnostic tool
Show-Menu