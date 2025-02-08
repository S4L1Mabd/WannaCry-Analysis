rule Milicious_Domain{
    meta:
        description = "This Rule For detecting the Malicious Domain and IPs In wannacary Rans"
        author = "Salim ABDOUNE"
        date = "2025-02-03"

    strings:
        $domain = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        
    
    condition:
        $domain
}

rule DetectAsInvoker {
    meta:
        description = "Detects requestedExecutionLevel set to asInvoker"
        author = "Salim ABDOUNE"
        date = "2025-02-03"

    strings:
        $asInvoker = "<requestedExecutionLevel level=\"asInvoker\" />"

    condition:
        $asInvoker
}


rule ProofOfWannacry {
    meta:
        description = "Detects Wannacry-related file extensions"
        author = "Salim ABDOUNE" 
        date = "2025-02-03"

    strings:
        $prof1 = ".wnryO"
        $prof2 = ".wnry"
        $prof3 = ".pky"
        $prof4 = ".eky"

    condition:
        any of ($prof1, $prof2, $prof3, $prof4)
}


rule Wannacy_Wallets {
    meta:
        description = "Detects Wannacry-related CryptoCurrency WAllet Addresses"
        author = "Salim ABDOUNE" 
        date = "2025-02-03"




    strings:
        $add1 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn"
        $add2 = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw"
        $add3 = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94"
     

    condition:
        any of ($add1, $add2, $add3)
}


rule Milicious_WinAPI {
    meta:
        description = "Detects Wannacry-related Windows API"
        author = "Salim ABDOUNE" 
        date = "2025-02-03"




    strings:
        $Api1 = "StartServiceA"
        $Api2 = "OpenSCManagerA"
        $Api3 = "CryptAcquireContextA"
        $Api4 = "CryptGenRandom"
        $Api5 = "OpenServiceA"
     

    condition:
        any of ($Api1, $Api2, $Api3, $Api4, $Api5)
}

