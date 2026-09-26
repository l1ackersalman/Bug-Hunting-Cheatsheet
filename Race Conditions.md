# Race Condition Exploits

- [Exploiting Limit Overrun Race Conditions](#exploiting-limit-overrun-race-conditions)
- [Bypassing Rate Limits with Race Conditions](#bypassing-rate-limits-with-race-conditions)
- [Multi-Endpoint Race Conditions](#multi-endpoint-race-conditions)
- [Exploiting Single-Endpoint Race Conditions and Time-Sensitive Vulnerabilities](#exploiting-single-endpoint-race-conditions-and-time-sensitive-vulnerabilities)

---

## Exploiting Limit Overrun Race Conditions

Suppose there is an e-commerce site that provides a discount coupon intended for one-time use. However, you can redeem this coupon multiple times or even indefinitely by exploiting race conditions.

**Exploit**

1. In Burp Repeater, copy the application's endpoint multiple times to trigger coupon redemption.
2. Create a tab group and send the group in parallel.

## Bypassing Rate Limits with Race Conditions

Suppose an application requires an OTP for actions, allowing only five invalid OTP attempts before locking the user for a limited time. This rate limit can be bypassed using race conditions.

**Exploit**

1. In Burp Intruder, create a custom resource pool with 10 or more concurrent requests.
2. Start the attack to potentially bypass the five-attempt rate limit by sending 10+ requests in a single packet.

> **Note:** In this type of scenario, the application may count multiple attempts sent within a single request as only **one attempt**. For example, if we send 10+ attempts in a single request, the application may only count it as 1 attempt. This means we may still have the remaining 4 attempts available and can send another 10+ attempts within a single request.

## Multi-Endpoint Race Conditions

[PortSwigger Lab](https://portswigger.net/web-security/race-conditions/lab-race-conditions-multi-endpoint)

## Exploiting Single-Endpoint Race Conditions and time-sensitive vulnerabilities

Suppose you request the `forgot password` endpoint to generate a reset password token for `attacker@mail.com`. Simultaneously, make another request for `victim@mail.com` and send both requests in a group tab using a parallel connection. If the endpoint is vulnerable to race conditions, it may send the victim's token to the attacker's email.

In Some cases, we might need to use different `session cookie+csrf token` for each user to exploit time sensitive vulnerabilities. Here is a lab for it.

[PortSwigger Lab: Exploiting time-sensitive vulnerabilities](https://portswigger.net/web-security/race-conditions/lab-race-conditions-exploiting-time-sensitive-vulnerabilities)
