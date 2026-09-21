This is the first of my python challenges with Claude.

I will write vulnerabilities and skills learned in a hidden format so if anyone would like to attempt solving them they don't get any spoilers.

<details>
  <summary>Click To Reveal</summary>
  
  Vulnbank had 3 main vulnerabilities. 
  
  - A hard coded backdoor password
  - IDOR within the view_profile section which allowed any user to request the api_key for another user
  - A command injection vulnerability in the admin_diagonstic function.
  
  Skills used:
  - Use of pythons socket module to create TCP/IP connections (to myself) to interact with the TCP server
  - Use of pythons JSON module to construct/deconstruct JSON objects.
  - Reviewing of code to identify flaws such as IDOR and command injection.
  </details>
