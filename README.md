<p><strong><h2>RequestRedactorX</h2></strong> RequestRedactorX is a Burp Suite extension designed to safely extract, clean, and share HTTP requests without exposing sensitive data. 
It provides a fast and flexible way to copy sanitized requests during pentesting, reporting, or team communication.</p>

<p>The extension introduces four powerful copy modes, giving full control over how requests are redacted.</p>

<h3>✨ Features</h3>

<ul>
  <li><strong>Copy without headers</strong><br>
      Generates a lightweight version of the request by removing all HTTP headers.
  </li>

  <li><strong>Copy with header censorship</strong><br>
      Automatically censors sensitive headers (e.g., Authorization, Cookies, Tokens) based on a customizable list.
  </li>

  <li><strong>Copy with parameter masking</strong><br>
      Masks sensitive parameters in:
      <ul>
        <li>URL query</li>
        <li>Body parameters</li>
      </ul>
      Users can define which parameter names should be masked.
  </li>

  <li><strong>Copy with full sanitization (headers + parameters)</strong><br>
      Produces a fully redacted request suitable for sending in tickets, Slack, or documentation without leaking secrets.
  </li>

  <li><strong>Dedicated UI panels</strong> to manage:
      <ul>
        <li>Sensitive headers list</li>
        <li>Parameter names for masking</li>
        <li>Redact/mask placeholders</li>
      </ul>
  </li>

  <li><strong>Clean, fast, minimal GUI</strong></li>
</ul>

<h3>How to use the extension</h3>

<p>To use the extension, follow these steps:</p>

<ol>
  <li>Install <strong>RequestRedactorX</strong> in Burp Suite.</li>
  
  <li>Open the extension panel and configure:
    <ul>
      <li>The list of sensitive headers to censor and placeholders</li>
        <img width="888" height="1716" alt="image" src="https://github.com/user-attachments/assets/f4671f51-74a1-4316-939d-e3a79c39edd8" />
    </li>
      <li>The parameter names that should be masked and placeholders</li>
      <img width="1096" height="1436" alt="image" src="https://github.com/user-attachments/assets/21427b5a-9cd4-47d3-9df5-d63e73a2f06b" />
    </ul>
  </li>

  <li>Right-click any HTTP request inside Burp Suite (Proxy, Repeater, Intruder, etc.).</li>

  <li>Select one of the available copy options:
    <ul>
      <li><strong>Copy request (headers sanitized)</strong></li>
      <li><strong>Copy request (headers/params redacted)</strong></li>
      <li><strong>Copy request (headers/params masked)</strong></li>
      <li><strong>Copy request (sanitize + redact + mask)</strong></li>
    </ul>
  </li>
  <img width="1300" height="186" alt="image" src="https://github.com/user-attachments/assets/cc1152a0-12ed-40ea-a37e-5f33591f846e" />

  <li>Paste the sanitized request wherever you need — reports, tickets, Slack, or documentation — without exposing sensitive data.</li>
</ol>



⸻

Example result

1. Original request
<pre>
POST /client/ HTTP/2
Host: localhost:32564
Cache-Control: max-age=0
Accept-Language: pl-PL,pl;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://localhost:32564/
Accept-Encoding: gzip, deflate, br
Cookie: access_token=eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IkhlbGxvVGhlcmUiLCJpc3MiOiJhZHZlbnR1cmVyIiwiZXhwIjoxNzY1NjMwMjQ3LjA1MTc1MDJ9.J8nxYMXkV2yfcl1rJuILxAxZdlkzNrCpdDLy6BKladbuAlqFlWGQXc8UJQ1brHjDlns1vRxr38N-mpKkeYgJbA
Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IkhlbGxvVGhlcmUiLCJpc3MiOiJhZHZlbnR1cmVyIiwiZXhwIjoxNzY1NjMwMjQ3LjA1MTc1MDJ9.J8nxYMXkV2yfcl1rJuILxAxZdlkzNrCpdDLy6BKladbuAlqFlWGQXc8UJQ1brHjDlns1vRxr38N-mpKkeYgJbA
Content-Type: application/x-www-form-urlencoded
Content-Length: 27

username=test&password=test
</pre>

2. Redacted request
<pre>
POST /client/ HTTP/2
Host: localhost:32564
Cache-Control: max-age=0
User-Agent: [...]
Referer: http://localhost:32564/
Cookie: [...REDACTED...]
Authorization: Bearer [...REDACTED...]
Content-Type: application/x-www-form-urlencoded
Content-Length: 27

username=[...]&password=[REDACTED]
</pre>


⸻

🔒 <strong>Why RequestRedactorX?</strong>

During pentests, bug bounty work, and code reviews, security engineers frequently need to share request samples.
Standard copy/paste often exposes tokens, session cookies, or PII.
RequestRedactorX eliminates this risk, transforming real traffic into safe, sanitized artifacts — instantly.

🛠️<strong> Ideal for</strong><br>
      <ul>
        <li>Pentesters</li>
        <li>Bug bounty hunters</li>
        <li>Security engineers</li>
        <li>Developers and QA teams needing safe HTTP samples</li>
      </ul>
