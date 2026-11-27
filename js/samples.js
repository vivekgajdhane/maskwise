/**
 * Realistic synthetic test payloads demonstrating every detector, validator,
 * redaction mode, pseudonym consistency, and decoy rejection case.
 */

export const SAMPLE_NOISY_TEXT = `[SUPPORT TICKET #INC-40912]
Reporter: Priya.Sharma@Acme.in (backup: priya.sharma+alerts@acme.in)
Callback requested on +91 98765 43210 or alternate +91-98765-43210.
Escalation contact: security-ops@sub.acme.co.in | +1 (415) 555-0199
Billing Visa used: 4532-0151-1283-0366 (note: prior retry failed on card 4532-0151-1283-0367).
Reference invoice ID: 987654321012345678 (do not flag as card or phone).

[RESUME SNIPPET — CANDIDATE APPLICATION]
Name: Rohan Kulkarni
Primary Email: rohan.kulkarni@mail.edu.in
Secondary Contact: 09876543210 | PAN: ABCPE1234F (Entity check invalid sample: ABCXE1234F)
Re-confirming applicant email: ROHAN.KULKARNI@MAIL.EDU.IN

[CLINICAL INTAKE NOTE]
Patient Aadhaar (UIDAI verified): 4521 8890 3129
Misread OCR Aadhaar decoy (fails Verhoeff): 4521 8890 3120
Insurer RuPay Card: 6070-9300-0012-3455 | Hospital Trust PAN: AAATC9021D
Follow-up email: priya.sharma@acme.in | Emergency: +91 98201 11223

[SERVER & AUTHENTICATION LOG]
2026-11-27T09:14:22Z auth_ok user=priya.sharma@acme.in src_ip=192.168.14.22 ipv6=2001:db8::8a2e:370:7334
2026-11-27T09:14:25Z health_check src_ip=::1 trace_id=1234-5678-9012-3456 (Luhn-invalid decoy)
2026-11-27T09:14:29Z parser_skip bad_ips=[999.1.1.1, 1.2.3.4.5, 192.168.01.1] amex=3782 822463 10005`;

export const SAMPLE_NOISY_CSV = `record_id,customer_name,contact_details,kyc_id,payment_token,source_ip,notes
101,"Sharma, Priya","Priya.Sharma@Acme.in
+91 98765 43210",4521 8890 3129,4532-0151-1283-0366,192.168.14.22,Primary onboarding
102,"Desai, Aarav",aarav.desai+billing@corp.in,ABCPE1234F,5425 2334 3010 9903,2001:db8::1,=CMD|'/C calc'!A0
103,"Sharma, Priya",priya.sharma@acme.in,+91-98765-43210,1234-5678-9012-3456,999.1.1.1,Repeat customer + decoys
104,"Nair, Meera",meera@clinic.org,7812-3456-9018,4532-0151-1283-0367,10.24.8.15,@SUM(1+1)`;
