document.addEventListener('DOMContentLoaded', function() {
    const content = document.querySelector('.content');
    const links = document.querySelectorAll('.sidebar a');

    const data = {
        https: {
            title: "HTTPS (HyperText Transfer Protocol Secure)",
            description: "HTTPS is an extension of HTTP that uses encryption to secure data transmission over the internet. It employs TLS (Transport Layer Security) to provide confidentiality, integrity, and authentication. Websites using HTTPS display a padlock icon in the browser, indicating a secure connection. This protocol prevents eavesdropping, tampering, and man-in-the-middle attacks by encrypting all data exchanged between the client and server.",
            prevention: "Always use HTTPS for websites, especially for sensitive data. Implement HSTS (HTTP Strict Transport Security) headers to enforce HTTPS connections."
        },
        tls: {
            title: "TLS (Transport Layer Security)",
            description: "TLS is a cryptographic protocol designed to provide secure communication over a computer network. It is the successor to SSL and is widely used for securing web traffic, email, VoIP, and other communications. TLS uses asymmetric cryptography for key exchange and symmetric encryption for data transmission, ensuring that data remains confidential and tamper-proof.",
            prevention: "Keep TLS libraries updated and use the latest versions (TLS 1.3 preferred). Disable older, vulnerable versions like SSL 2.0/3.0 and TLS 1.0/1.1."
        },
        ssh: {
            title: "SSH (Secure Shell)",
            description: "SSH is a network protocol that provides a secure way to access a computer over an unsecured network. It uses public-key cryptography to authenticate the remote computer and allow the client to authenticate itself. SSH is commonly used for remote command-line login, remote command execution, and secure file transfer.",
            prevention: "Use strong, unique passwords or key-based authentication. Disable password authentication if using keys. Keep SSH server software updated and use non-standard ports to reduce automated attacks."
        },
        ipsec: {
            title: "IPsec (Internet Protocol Security)",
            description: "IPsec is a suite of protocols for securing IP communications by authenticating and encrypting each IP packet in a data stream. It operates at the network layer and can be used to create VPNs (Virtual Private Networks). IPsec provides confidentiality, integrity, and authentication services for IP packets.",
            prevention: "Implement IPsec in VPN configurations. Use strong encryption algorithms and regularly rotate keys. Ensure proper configuration to avoid vulnerabilities."
        },
        oauth: {
            title: "OAuth",
            description: "OAuth is an open standard for access delegation, commonly used for token-based authentication and authorization. It allows third-party applications to access user resources without exposing credentials. OAuth 2.0 is the current version and supports various grant types for different use cases, such as web applications and mobile apps.",
            prevention: "Use OAuth 2.0 with PKCE (Proof Key for Code Exchange) for public clients. Implement proper token storage and validation. Regularly audit and revoke unnecessary permissions."
        },
        saml: {
            title: "SAML (Security Assertion Markup Language)",
            description: "SAML is an XML-based open standard for exchanging authentication and authorization data between parties, particularly between an identity provider and a service provider. It enables single sign-on (SSO) across different domains and is commonly used in enterprise environments for federated identity management.",
            prevention: "Use HTTPS for SAML communications. Validate SAML assertions properly to prevent XML signature wrapping attacks. Keep SAML libraries updated."
        },
        "sql-injection": {
            title: "SQL Injection",
            description: "SQL injection is a code injection technique that exploits vulnerabilities in an application's software by inserting malicious SQL code into a query. This can allow attackers to view, modify, or delete data in the database, potentially leading to unauthorized access or data breaches. It occurs when user input is not properly sanitized before being used in SQL queries.",
            prevention: "Use prepared statements and parameterized queries. Implement input validation and sanitization. Employ web application firewalls (WAF) and least privilege principles for database accounts."
        },
        xss: {
            title: "Cross-Site Scripting (XSS)",
            description: "XSS is a type of injection attack where malicious scripts are injected into otherwise benign and trusted websites. These scripts can steal cookies, session tokens, or other sensitive information, or perform actions on behalf of the user. XSS occurs when web applications fail to properly escape user-supplied data before rendering it in HTML.",
            prevention: "Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers. Employ XSS filters and sanitize user input."
        },
        csrf: {
            title: "Cross-Site Request Forgery (CSRF)",
            description: "CSRF is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. This is done by tricking the user's browser into sending a forged HTTP request, along with the user's session cookie, to a vulnerable web application. The attack exploits the trust that a site has in the user's browser.",
            prevention: "Implement CSRF tokens in forms. Use SameSite cookie attributes. Validate the Origin and Referer headers. Employ anti-CSRF measures in web frameworks."
        },
        mitm: {
            title: "Man-in-the-Middle (MitM)",
            description: "MitM attacks occur when an attacker intercepts and possibly alters the communication between two parties who believe they are directly communicating with each other. This can happen on insecure networks or through DNS spoofing. The attacker can eavesdrop on conversations, steal sensitive information, or inject malicious content.",
            prevention: "Use HTTPS everywhere. Implement certificate pinning. Avoid public Wi-Fi for sensitive communications. Use VPNs for secure connections."
        },
        phishing: {
            title: "Phishing",
            description: "Phishing is a cyber attack where attackers impersonate trustworthy entities to deceive individuals into revealing sensitive information such as passwords, credit card numbers, or other personal data. This is typically done through fraudulent emails, websites, or messages that appear legitimate. Phishing exploits human psychology rather than technical vulnerabilities.",
            prevention: "Educate users about phishing tactics. Implement email filters and anti-phishing tools. Use multi-factor authentication (MFA). Verify suspicious communications through alternative channels."
        },
        dos: {
            title: "Denial of Service (DoS)",
            description: "DoS attacks aim to make a service unavailable by overwhelming it with traffic from multiple sources. This prevents legitimate users from accessing the service. Distributed DoS (DDoS) attacks use botnets to amplify the attack. DoS can target network bandwidth, system resources, or application vulnerabilities.",
            prevention: "Implement rate limiting and traffic filtering. Use DDoS protection services. Keep systems patched and monitor for unusual traffic patterns. Design applications with resilience in mind."
        },
        "buffer-overflow": {
            title: "Buffer Overflow",
            description: "Buffer overflow occurs when a program writes more data to a buffer than it can hold, causing adjacent memory to be overwritten. This can lead to crashes, data corruption, or execution of arbitrary code. Buffer overflows are often exploited to gain unauthorized access or escalate privileges in software vulnerabilities.",
            prevention: "Use safe programming practices like bounds checking. Employ compiler protections like stack canaries and ASLR. Keep software updated and use memory-safe languages when possible."
        },
        "weak-passwords": {
            title: "Weak Passwords",
            description: "Weak passwords are easily guessable or crackable passwords that provide insufficient protection against brute-force or dictionary attacks. Common weak passwords include simple words, sequential numbers, or personal information. Using weak passwords increases the risk of unauthorized account access and data breaches.",
            prevention: "Enforce strong password policies (length, complexity). Implement password managers. Use multi-factor authentication (MFA). Educate users on password best practices."
        },
        "unpatched-software": {
            title: "Unpatched Software",
            description: "Failing to apply security updates and patches leaves systems vulnerable to known exploits. Software vendors regularly release patches to fix security flaws, but many systems remain unpatched due to negligence, compatibility issues, or lack of awareness. This creates opportunities for attackers to exploit known vulnerabilities.",
            prevention: "Implement automated patch management systems. Regularly scan for vulnerabilities. Test patches in staging environments before deployment. Stay informed about security advisories."
        },
        "open-ports": {
            title: "Open Ports",
            description: "Leaving unnecessary network ports open exposes systems to potential attacks. Open ports can be scanned by attackers looking for vulnerable services. Services running on open ports may have known vulnerabilities or weak configurations that can be exploited.",
            prevention: "Conduct regular port scans and close unnecessary ports. Use firewalls to restrict access. Implement network segmentation. Keep services updated and properly configured."
        },
        "default-credentials": {
            title: "Default Credentials",
            description: "Many devices and software come with default usernames and passwords that are well-known and easily obtainable. Failing to change these defaults allows attackers to gain unauthorized access. This is a common issue with IoT devices, routers, and administrative interfaces.",
            prevention: "Change all default credentials immediately after setup. Use unique, strong passwords. Disable default accounts if possible. Implement credential management policies."
        },
        "improper-access": {
            title: "Improper Access Controls",
            description: "Improper access controls occur when systems grant excessive permissions to users or fail to restrict access appropriately. This can lead to privilege escalation, unauthorized data access, or unintended actions. Common issues include misconfigured role-based access control (RBAC) or overly permissive file permissions.",
            prevention: "Implement the principle of least privilege. Use role-based access control (RBAC). Regularly audit permissions and access logs. Employ access control lists (ACLs) and mandatory access controls (MAC)."
        },
        "lack-encryption": {
            title: "Lack of Encryption",
            description: "Storing or transmitting sensitive data without encryption leaves it vulnerable to interception or unauthorized access. Unencrypted data can be easily read by anyone with access to the storage medium or network traffic. This is particularly critical for personal information, financial data, and intellectual property.",
            prevention: "Encrypt data at rest and in transit. Use strong encryption algorithms. Implement proper key management. Comply with data protection regulations like GDPR or HIPAA."
        },
        "verbose-errors": {
            title: "Verbose Error Messages",
            description: "Verbose error messages that reveal internal system details, such as stack traces, database schemas, or file paths, can provide valuable information to attackers. This information can be used to craft more targeted attacks or gain insights into system architecture and potential vulnerabilities.",
            prevention: "Implement generic error messages for users. Log detailed errors internally for debugging. Use error handling frameworks that sanitize output. Conduct security code reviews."
        }
    };

    links.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const item = this.getAttribute('data-item');
            const itemData = data[item];
            if (itemData) {
                content.innerHTML = `
                    <h2>${itemData.title}</h2>
                    <p><strong>Description:</strong> ${itemData.description}</p>
                    <p><strong>Prevention/Mitigation:</strong> ${itemData.prevention}</p>
                `;
            }
        });
    });
});