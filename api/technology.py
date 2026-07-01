from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Any

from api.capabilities import NOT_DETECTED, VERIFICATION_FAILED
from api.models import TechnologyDetection, TechnologyProfile
from api.utils import hostname_for, normalize_url


USER_AGENT = "BeaconAudit/0.1"


class HeadParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.meta: list[dict[str, str]] = []
        self.scripts: list[str] = []
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "meta":
            self.meta.append(attrs_dict)
        elif tag.lower() == "script" and attrs_dict.get("src"):
            self.scripts.append(attrs_dict["src"])
        elif tag.lower() == "link" and attrs_dict.get("href"):
            self.links.append(attrs_dict["href"])


class TechnologyFingerprinter:
    def __init__(self, timeout_seconds: int = 8) -> None:
        self.timeout_seconds = timeout_seconds

    def fingerprint(self, target_url: str) -> TechnologyProfile:
        url = normalize_url(target_url)
        host = hostname_for(url)
        domain = self._registered_domain(host)
        page = self._fetch_page(url)
        body = page["body"].lower()
        headers = {key.lower(): value for key, value in page["headers"].items()}
        parser = HeadParser()
        parser.feed(page["body"])
        ips = self._resolve_ips(host)
        rdap_domain = self._rdap_json(f"https://rdap.org/domain/{domain}")
        rdap_ip = self._rdap_json(f"https://rdap.org/ip/{ips[0]}") if ips else None
        dns = self._dns_public_records(domain)
        raw = {
            "url": url,
            "host": host,
            "registered_domain": domain,
            "headers": headers,
            "scripts": parser.scripts[:50],
            "links": parser.links[:50],
            "ips": ips,
            "dns": dns,
            "rdap_domain_available": rdap_domain is not None,
            "rdap_ip_available": rdap_ip is not None,
            "page_fetch_error": page.get("error"),
            "page_fetch_status": VERIFICATION_FAILED if page.get("error") else "Verified",
        }

        return TechnologyProfile(
            target_url=url,
            domain=self._domain_profile(domain, rdap_domain),
            dns=self._dns_profile(dns),
            hosting=self._hosting_profile(headers, body, rdap_ip, ips),
            platform=self._platform_profile(headers, body, parser, page.get("error"), ips),
            frameworks=self._framework_profile(body, parser, page.get("error")),
            analytics=self._analytics_profile(body, parser, page.get("error")),
            infrastructure=self._infrastructure_profile(headers, body, page.get("error")),
            email=self._email_profile(dns),
            cms=self._cms_profile(body, parser),
            migration_assessment=self._migration_profile(headers, body, parser, dns, rdap_ip, ips),
            raw_evidence=raw,
        )

    def _fetch_page(self, url: str) -> dict[str, Any]:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                return {
                    "status_code": response.status,
                    "final_url": response.url,
                    "headers": dict(response.headers.items()),
                    "body": response.read(750_000).decode("utf-8", "ignore"),
                }
        except urllib.error.HTTPError as exc:
            return {
                "status_code": exc.code,
                "final_url": exc.url,
                "headers": dict(exc.headers.items()),
                "body": exc.read(250_000).decode("utf-8", "ignore"),
                "error": str(exc),
            }
        except OSError as exc:
            return {"status_code": None, "final_url": url, "headers": {}, "body": "", "error": str(exc)}

    def _resolve_ips(self, host: str) -> list[str]:
        try:
            return sorted({item[4][0] for item in socket.getaddrinfo(host, 443, socket.AF_INET)})
        except OSError:
            return []

    def _rdap_json(self, url: str) -> dict[str, Any] | None:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json, application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                return json.loads(response.read(1_000_000).decode("utf-8", "ignore"))
        except (OSError, json.JSONDecodeError):
            return None

    def _dns_public_records(self, host: str) -> dict[str, Any]:
        records: dict[str, Any] = {"nameservers": [], "txt": [], "spf": None, "dmarc": None, "dnssec": None, "provider": None}
        try:
            import dns.resolver  # type: ignore[import-not-found]
        except ImportError:
            records["lookup"] = "dns_over_https"
            return self._dns_over_https_records(host, records)

        try:
            records["nameservers"] = sorted(str(record.target).rstrip(".") for record in dns.resolver.resolve(host, "NS", lifetime=4))
        except Exception as exc:
            records["ns_error"] = str(exc)
        try:
            txt = ["".join(part.decode("utf-8", "ignore") for part in record.strings) for record in dns.resolver.resolve(host, "TXT", lifetime=4)]
            records["txt"] = txt
            records["spf"] = next((item for item in txt if item.lower().startswith("v=spf1")), None)
        except Exception as exc:
            records["txt_error"] = str(exc)
        try:
            dmarc = ["".join(part.decode("utf-8", "ignore") for part in record.strings) for record in dns.resolver.resolve(f"_dmarc.{host}", "TXT", lifetime=4)]
            records["dmarc"] = next((item for item in dmarc if item.lower().startswith("v=dmarc1")), None)
        except Exception as exc:
            records["dmarc_error"] = str(exc)
        try:
            records["dnssec"] = bool(list(dns.resolver.resolve(host, "DS", lifetime=4)))
        except Exception:
            records["dnssec"] = False
        records["provider"] = self._dns_provider(records["nameservers"])
        return records

    def _dns_over_https_records(self, host: str, records: dict[str, Any]) -> dict[str, Any]:
        ns_answers = self._doh(host, "NS")
        records["nameservers"] = sorted(answer.rstrip(".") for answer in ns_answers)
        txt_answers = self._doh(host, "TXT")
        records["txt"] = txt_answers
        records["spf"] = next((item for item in txt_answers if item.lower().startswith("v=spf1")), None)
        dmarc_answers = self._doh(f"_dmarc.{host}", "TXT")
        records["dmarc"] = next((item for item in dmarc_answers if item.lower().startswith("v=dmarc1")), None)
        records["dnssec"] = bool(self._doh(host, "DS"))
        records["provider"] = self._dns_provider(records["nameservers"])
        return records

    def _doh(self, name: str, record_type: str) -> list[str]:
        url = f"https://dns.google/resolve?name={urllib.parse.quote(name)}&type={urllib.parse.quote(record_type)}"
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/dns-json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read(500_000).decode("utf-8", "ignore"))
        except (OSError, json.JSONDecodeError):
            return []
        answers = []
        for answer in payload.get("Answer", []) or []:
            data = str(answer.get("data", "")).strip()
            if record_type == "TXT":
                data = data.replace('" "', "").strip('"')
            if data:
                answers.append(data)
        return answers

    def _domain_profile(self, host: str, rdap: dict[str, Any] | None) -> dict[str, TechnologyDetection]:
        registrar = self._unknown("Registrar", "RDAP data Not Detected")
        expiration = self._unknown("Domain expiration", "RDAP expiration event Not Detected")
        if rdap:
            registrar_name = rdap.get("registrarName")
            if not registrar_name:
                for entity in rdap.get("entities", []):
                    if "registrar" in entity.get("roles", []):
                        registrar_name = self._entity_name(entity)
                        break
            if registrar_name:
                registrar = self._det("Registrar", registrar_name, "High", ["RDAP registrar field/entity"])
            for event in rdap.get("events", []):
                if event.get("eventAction") in {"expiration", "registration expiration"} and event.get("eventDate"):
                    expiration = self._det("Domain expiration", event["eventDate"], "High", ["RDAP expiration event"])
                    break
        return {"domain": self._det("Domain", host, "High", ["Submitted URL hostname"]), "registrar": registrar, "expiration": expiration}

    def _dns_profile(self, dns: dict[str, Any]) -> dict[str, TechnologyDetection]:
        nameservers = dns.get("nameservers") or []
        return {
            "nameservers": self._det("Nameservers", ", ".join(nameservers), "High", ["DNS NS records"]) if nameservers else self._unknown("Nameservers", "NS records Not Detected"),
            "dns_provider": self._det("DNS provider", dns["provider"], "Medium", ["Nameserver hostname pattern"]) if dns.get("provider") else self._unknown("DNS provider", "Provider pattern not detected"),
            "dnssec_enabled": self._det("DNSSEC enabled", str(bool(dns.get("dnssec"))), "Medium", ["DNS DS query"]),
        }

    def _hosting_profile(self, headers: dict[str, str], body: str, rdap_ip: dict[str, Any] | None, ips: list[str]) -> dict[str, TechnologyDetection]:
        ip_owner = self._unknown("IP owner", "IP RDAP data Not Detected")
        asn = self._unknown("ASN", "IP RDAP data Not Detected")
        if rdap_ip:
            owner = rdap_ip.get("name") or self._entity_name((rdap_ip.get("entities") or [{}])[0])
            if owner:
                ip_owner = self._det("IP owner", owner, "High", ["IP RDAP name/entity"])
            if rdap_ip.get("handle"):
                asn = self._det("ASN", rdap_ip["handle"], "Medium", ["IP RDAP handle"])
        cdn = self._cdn(headers, body, ips)
        provider = self._hosting_provider(headers, body, ip_owner.value, ips)
        return {
            "hosting_provider": provider,
            "cdn": cdn,
            "edge_network": TechnologyDetection("Edge network", cdn.value, cdn.confidence, cdn.evidence),
            "ip_owner": ip_owner,
            "asn": asn,
            "ip_addresses": self._det("IP addresses", ", ".join(ips), "High", ["A record resolution"]) if ips else self._unknown("IP addresses", "A records Not Detected"),
        }

    def _platform_profile(
        self,
        headers: dict[str, str],
        body: str,
        parser: HeadParser,
        page_error: object = None,
        ips: list[str] | None = None,
    ) -> dict[str, TechnologyDetection]:
        if page_error:
            detections = {
                key: self._verification_failed(name, f"Page fetch failed: {page_error}")
                for key, name in {
                    "wordpress": "WordPress",
                    "wix": "Wix",
                    "squarespace": "Squarespace",
                    "shopify": "Shopify",
                    "godaddy_builder": "GoDaddy Builder",
                    "webflow": "Webflow",
                    "react": "React",
                    "next_js": "Next.js",
                    "vue": "Vue",
                    "angular": "Angular",
                    "static_html": "Static HTML",
                }.items()
            }
            if self._is_godaddy_site_ip_pair(ips or []):
                detections["godaddy_builder"] = self._det(
                    "GoDaddy Builder",
                    "GoDaddy Builder",
                    "Medium",
                    ["Resolved IP pair commonly used by GoDaddy Websites + Marketing"],
                )
            return detections
        detections = {
            "wordpress": self._present("WordPress", "wp-content" in body or "wp-includes" in body, "High", "wp-content/wp-includes in HTML"),
            "wix": self._present("Wix", "wixstatic.com" in body or "x-seen-by" in headers, "High", "Wix static/header indicators"),
            "squarespace": self._present("Squarespace", "squarespace" in body, "High", "Squarespace HTML asset indicators"),
            "shopify": self._present("Shopify", "cdn.shopify.com" in body or "shopify" in body, "High", "Shopify asset indicators"),
            "godaddy_builder": self._present("GoDaddy Builder", ("godaddy" in body and "websitebuilder" in body) or "filler@godaddy.com" in body or "godaddysites" in body, "Medium", "GoDaddy builder text/assets"),
            "webflow": self._present("Webflow", "webflow" in body or "data-wf-page" in body, "High", "Webflow markers"),
            "react": self._present("React", "react" in body or "data-reactroot" in body, "Medium", "React script/DOM markers"),
            "next_js": self._present("Next.js", "/_next/" in body or "__next_data__" in body, "High", "Next.js asset/data markers"),
            "vue": self._present("Vue", "vue" in body or "data-v-" in body, "Medium", "Vue markers"),
            "angular": self._present("Angular", "ng-version" in body or "angular" in body, "Medium", "Angular markers"),
        }
        if all(item.value == NOT_DETECTED for item in detections.values()):
            detections["static_html"] = self._det("Static HTML", "Static HTML", "Medium", ["No CMS/app framework markers detected"])
        else:
            detections["static_html"] = self._unknown("Static HTML", "Application/CMS markers detected")
        return detections

    def _framework_profile(self, body: str, parser: HeadParser, page_error: object = None) -> dict[str, TechnologyDetection]:
        if page_error:
            return {
                key: self._verification_failed(name, f"Page fetch failed: {page_error}")
                for key, name in {
                    "bootstrap": "Bootstrap",
                    "tailwind": "Tailwind",
                    "jquery": "jQuery",
                    "react": "React",
                    "vue": "Vue",
                    "next_js": "Next.js",
                    "astro": "Astro",
                    "alpine_js": "Alpine.js",
                }.items()
            }
        return {
            "bootstrap": self._present("Bootstrap", "bootstrap" in body, "Medium", "Bootstrap asset/class marker"),
            "tailwind": self._present("Tailwind", "tailwind" in body or re.search(r"\b(?:sm|md|lg|xl):[a-z-]+", body) is not None, "Medium", "Tailwind asset/responsive class marker"),
            "jquery": self._present("jQuery", "jquery" in body, "High", "jQuery asset marker"),
            "react": self._present("React", "react" in body or "data-reactroot" in body, "Medium", "React marker"),
            "vue": self._present("Vue", "vue" in body or "data-v-" in body, "Medium", "Vue marker"),
            "next_js": self._present("Next.js", "/_next/" in body or "__next_data__" in body, "High", "Next.js marker"),
            "astro": self._present("Astro", "astro-" in body or "/_astro/" in body, "High", "Astro asset marker"),
            "alpine_js": self._present("Alpine.js", "alpinejs" in body or "x-data" in body, "Medium", "Alpine marker"),
        }

    def _analytics_profile(self, body: str, parser: HeadParser, page_error: object = None) -> dict[str, TechnologyDetection]:
        if page_error:
            return {
                key: self._verification_failed(name, f"Page fetch failed: {page_error}")
                for key, name in {
                    "google_analytics": "Google Analytics",
                    "google_tag_manager": "Google Tag Manager",
                    "microsoft_clarity": "Microsoft Clarity",
                    "meta_pixel": "Meta Pixel",
                    "linkedin_insight": "LinkedIn Insight",
                    "hotjar": "Hotjar",
                }.items()
            }
        return {
            "google_analytics": self._present("Google Analytics", "google-analytics.com" in body or "gtag(" in body or "ga(" in body, "High", "GA script/function marker"),
            "google_tag_manager": self._present("Google Tag Manager", "googletagmanager.com/gtm.js" in body or "gtm-" in body, "High", "GTM marker"),
            "microsoft_clarity": self._present("Microsoft Clarity", "clarity.ms" in body or "clarity(" in body, "High", "Clarity marker"),
            "meta_pixel": self._present("Meta Pixel", "connect.facebook.net" in body or "fbq(" in body, "High", "Meta Pixel marker"),
            "linkedin_insight": self._present("LinkedIn Insight", "snap.licdn.com" in body or "_linkedin_partner_id" in body, "High", "LinkedIn Insight marker"),
            "hotjar": self._present("Hotjar", "hotjar.com" in body or "hj(" in body, "High", "Hotjar marker"),
        }

    def _infrastructure_profile(self, headers: dict[str, str], body: str, page_error: object = None) -> dict[str, TechnologyDetection]:
        server = headers.get("server")
        if page_error and not server:
            server_detection = self._verification_failed("HTTP server", f"Page fetch failed: {page_error}")
        else:
            server_detection = self._det("HTTP server", server, "High", ["Server response header"]) if server else self._unknown("HTTP server", "Server header Not Detected")
        return {
            "http_server": server_detection,
            "reverse_proxy": self._reverse_proxy(headers),
            "cloudflare": self._present("Cloudflare", "cf-ray" in headers or "cloudflare" in headers.get("server", "").lower(), "High", "Cloudflare response headers"),
            "cloudfront": self._present("CloudFront", "x-amz-cf-id" in headers or "cloudfront" in headers.get("x-cache", "").lower(), "High", "CloudFront response headers"),
            "fastly": self._present("Fastly", "fastly" in headers.get("server", "").lower() or "x-served-by" in headers, "High", "Fastly response headers"),
            "akamai": self._present("Akamai", "akamai" in body or any("akamai" in value.lower() for value in headers.values()), "Medium", "Akamai header/body marker"),
            "nginx": self._present("Nginx", "nginx" in headers.get("server", "").lower(), "High", "Server header"),
            "apache": self._present("Apache", "apache" in headers.get("server", "").lower(), "High", "Server header"),
        }

    def _email_profile(self, dns: dict[str, Any]) -> dict[str, TechnologyDetection]:
        return {
            "spf": self._det("SPF", dns["spf"], "High", ["DNS TXT SPF record"]) if dns.get("spf") else self._unknown("SPF", "SPF record Not Detected or TXT verification failed"),
            "dkim": self._unknown("DKIM", "DKIM selector is not publicly inferable without a known selector"),
            "dmarc": self._det("DMARC", dns["dmarc"], "High", ["_dmarc TXT record"]) if dns.get("dmarc") else self._unknown("DMARC", "DMARC record Not Detected or TXT verification failed"),
        }

    def _cms_profile(self, body: str, parser: HeadParser) -> dict[str, TechnologyDetection]:
        generator = next((meta.get("content", "") for meta in parser.meta if meta.get("name", "").lower() == "generator"), "")
        wp_version = self._unknown("WordPress version", "Version not publicly exposed")
        if "wordpress" in generator.lower():
            wp_version = self._det("WordPress version", generator, "Medium", ["generator meta tag"])
        theme = self._regex_detection("WordPress theme", body, r"wp-content/themes/([^/'\"?\s]+)", "High", "wp-content theme path")
        plugins = sorted(set(re.findall(r"wp-content/plugins/([^/'\"?\s]+)", body)))[:20]
        return {
            "wordpress_version": wp_version,
            "theme": theme,
            "plugins": self._det("Plugins", ", ".join(plugins), "High", ["Public wp-content/plugins paths"]) if plugins else self._unknown("Plugins", "No public plugin paths detected"),
        }

    def _migration_profile(
        self,
        headers: dict[str, str],
        body: str,
        parser: HeadParser,
        dns: dict[str, Any],
        rdap_ip: dict[str, Any] | None,
        ips: list[str] | None = None,
    ) -> dict[str, TechnologyDetection]:
        platform = self._platform_profile(headers, body, parser)
        if platform["wix"].value != NOT_DETECTED or platform["squarespace"].value != NOT_DETECTED or platform["shopify"].value != NOT_DETECTED:
            difficulty = self._det("Migration difficulty", "Medium", "Medium", ["Hosted builder/ecommerce platform detected"])
            strategy = self._det("Recommended strategy", "Optimize existing", "Medium", ["Hosted platform detected; migration may not be first fix"])
        elif self._is_godaddy_site_ip_pair(ips or []):
            difficulty = self._det("Migration difficulty", "Medium", "Medium", ["GoDaddy Websites + Marketing IP pattern detected"])
            strategy = self._det("Recommended strategy", "Optimize existing", "Medium", ["Hosted builder platform can often be remediated in place first"])
        elif platform["wordpress"].value != NOT_DETECTED:
            difficulty = self._det("Migration difficulty", "Medium", "Medium", ["WordPress detected"])
            strategy = self._det("Recommended strategy", "Optimize existing", "Medium", ["WordPress can often be remediated in place"])
        elif dns.get("provider") != "Cloudflare":
            difficulty = self._det("Migration difficulty", "Low", "Medium", ["No complex platform marker detected"])
            strategy = self._det("Recommended strategy", "Move DNS to Cloudflare", "Medium", ["DNS provider is not clearly Cloudflare"])
        else:
            difficulty = self._det("Migration difficulty", "Low", "Medium", ["No complex platform marker detected"])
            strategy = self._det("Recommended strategy", "Leave in place", "Medium", ["No migration trigger detected"])
        return {"migration_difficulty": difficulty, "recommended_strategy": strategy}

    def _dns_provider(self, nameservers: list[str]) -> str | None:
        joined = " ".join(nameservers).lower()
        providers = {
            "Cloudflare": ["cloudflare"],
            "GoDaddy": ["domaincontrol"],
            "AWS Route 53": ["awsdns"],
            "Azure DNS": ["azure-dns"],
            "Google Cloud DNS": ["googledomains", "google"],
            "Squarespace": ["squarespacedns"],
            "Wix": ["wixdns"],
        }
        for provider, markers in providers.items():
            if any(marker in joined for marker in markers):
                return provider
        return None

    def _cdn(self, headers: dict[str, str], body: str, ips: list[str] | None = None) -> TechnologyDetection:
        if "cf-ray" in headers or "cloudflare" in headers.get("server", "").lower():
            return self._det("CDN", "Cloudflare", "High", ["Cloudflare response headers"])
        if "x-amz-cf-id" in headers or "cloudfront" in headers.get("x-cache", "").lower():
            return self._det("CDN", "CloudFront", "High", ["CloudFront response headers"])
        if ips and any(self._is_common_cloudfront_ip(ip) for ip in ips):
            return self._det("CDN", "CloudFront", "Medium", ["Resolved IP address is in a common CloudFront range"])
        if "x-served-by" in headers or "fastly" in headers.get("server", "").lower():
            return self._det("CDN", "Fastly", "High", ["Fastly response headers"])
        if "akamai" in body:
            return self._det("CDN", "Akamai", "Medium", ["Akamai body marker"])
        return self._unknown("CDN", "CDN response headers not detected")

    def _hosting_provider(self, headers: dict[str, str], body: str, ip_owner: str, ips: list[str] | None = None) -> TechnologyDetection:
        haystack = f"{headers} {body} {ip_owner} {' '.join(ips or [])}".lower()
        if "cloudfront" in haystack:
            return self._det("Hosting provider", "Amazon CloudFront", "High", ["CloudFront header/body/IP marker"])
        if ips and any(self._is_common_cloudfront_ip(ip) for ip in ips):
            return self._det("Hosting provider", "Amazon CloudFront", "Medium", ["Resolved IP address is in a common CloudFront range"])
        if self._is_godaddy_site_ip_pair(ips or []):
            return self._det("Hosting provider", "GoDaddy", "Medium", ["Resolved IP pair commonly used by GoDaddy Websites + Marketing"])
        providers = {
            "AWS": ["amazon", "aws", "cloudfront"],
            "Azure": ["azure"],
            "Cloudflare": ["cloudflare"],
            "GoDaddy": ["godaddy"],
            "Squarespace": ["squarespace"],
            "Wix": ["wix"],
            "Shopify": ["shopify"],
            "Webflow": ["webflow"],
        }
        for provider, markers in providers.items():
            if any(marker in haystack for marker in markers):
                return self._det("Hosting provider", provider, "Medium", ["Header/body/IP owner marker"])
        return self._unknown("Hosting provider", "Public headers and IP owner did not identify provider")

    def _is_godaddy_site_ip_pair(self, ips: list[str]) -> bool:
        return {"13.248.243.5", "76.223.105.230"}.issubset(set(ips))

    def _is_common_cloudfront_ip(self, ip: str) -> bool:
        prefixes = (
            "3.160.",
            "3.161.",
            "3.162.",
            "3.163.",
            "13.32.",
            "13.33.",
            "13.35.",
            "13.224.",
            "13.225.",
            "13.249.",
            "18.64.",
            "18.65.",
            "18.66.",
            "18.67.",
            "52.84.",
            "52.85.",
            "54.192.",
            "54.230.",
        )
        return ip.startswith(prefixes)

    def _reverse_proxy(self, headers: dict[str, str]) -> TechnologyDetection:
        proxy_headers = ["cf-ray", "x-amz-cf-id", "x-cache", "x-served-by", "via"]
        hits = [header for header in proxy_headers if header in headers]
        return self._det("Reverse proxy", ", ".join(hits), "High", ["Proxy/CDN response headers"]) if hits else self._unknown("Reverse proxy", "Proxy headers not detected")

    def _regex_detection(self, name: str, body: str, pattern: str, confidence: str, evidence: str) -> TechnologyDetection:
        match = re.search(pattern, body)
        return self._det(name, match.group(1), confidence, [evidence]) if match else self._unknown(name, f"{evidence} not detected")

    def _present(self, name: str, present: bool, confidence: str, evidence: str) -> TechnologyDetection:
        return self._det(name, name, confidence, [evidence]) if present else self._unknown(name, f"{evidence} not detected")

    def _det(self, name: str, value: str, confidence: str, evidence: list[str]) -> TechnologyDetection:
        if confidence == "Low":
            return TechnologyDetection(name, NOT_DETECTED, "Low", evidence)
        return TechnologyDetection(name, str(value), confidence, evidence)

    def _unknown(self, name: str, evidence: str) -> TechnologyDetection:
        return TechnologyDetection(name, NOT_DETECTED, "Low", [evidence])

    def _verification_failed(self, name: str, evidence: str) -> TechnologyDetection:
        return TechnologyDetection(name, VERIFICATION_FAILED, VERIFICATION_FAILED, [evidence])

    def _entity_name(self, entity: dict[str, Any]) -> str | None:
        vcard = entity.get("vcardArray")
        if not isinstance(vcard, list) or len(vcard) < 2:
            return None
        for item in vcard[1]:
            if item and item[0] == "fn" and len(item) > 3:
                return item[3]
        return None

    def _registered_domain(self, host: str) -> str:
        labels = host.lower().strip(".").split(".")
        if len(labels) <= 2:
            return host.lower()
        # Conservative fallback without a public suffix dependency. It handles the common
        # business-site cases Beacon currently targets and avoids querying RDAP for "www".
        if labels[-2] in {"co", "com", "net", "org"} and len(labels) >= 3:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])
