rule SUSP_LNX_Base64_Download_Exec_Apr24 : SCRIPT {
   meta:
      description = "Detects suspicious base64 encoded shell commands used for downloading and executing further stages"
      author = "Paul Hager"
      date = "2024-04-18"
      reference = "Internal Research"
      score = 75
      id = "df8dddef-3c49-500c-abc8-7f7de5aa69ae"
   strings:
      $sa1 = "curl http" base64
      $sa2 = "wget http" base64
      
      $sb1 = "chmod 777 " base64
      $sb2 = "/tmp/" base64
   condition:
      1 of ($sa*)
      and all of ($sb*)
}

rule SUSP_PY_Import_Statement_Apr24_1 {
   meta:
      description = "Detects suspicious Python import statement and socket usage often found in Python reverse shells"
      author = "Florian Roth"
      reference = "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/"
      date = "2024-04-15"
      score = 65
      id = "8e05f9a1-40a8-5d01-9e45-8779b0ff7a45"
   strings:
      $x1 = "import sys,socket,os,pty;s=socket.socket("
   condition:
      1 of them
}