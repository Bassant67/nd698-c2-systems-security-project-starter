rule unknown_threat
{
    meta:
        author = "Bassant"
        date = "2025-06-07"
        description = "Detects the SSH-One malware with hardcoded callout URLs"

    strings:
        $url1 = "http://darkl0rd.com:7758/SSH-One"
        $url2 = "http://darkl0rd.com:7758/SSH-T"

    condition:
        any of ($url1, $url2)
}
