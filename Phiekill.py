#!/usr/bin/env python3
"""
Phishing URL Detection Tool
Rule-based analyzer for detecting suspicious URLs
"""

import re
import urllib.parse
import tldextract
from typing import Dict, List, Tuple
import argparse
import sys
from datetime import datetime

def display_header():
    """Display tool header with creator information"""
    header = f"""
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗██╗     ██╗     
██╔══██╗██║  ██║██║██╔════╝██║ ██╔╝██║██║     ██║     
██████╔╝███████║██║█████╗  █████╔╝ ██║██║     ██║     
██╔═══╝ ██╔══██║██║██╔══╝  ██╔═██╗ ██║██║     ██║     
██║     ██║  ██║██║███████╗██║  ██╗██║███████╗███████╗
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝

        Advanced URL Threat Detection System
            Created by: CyberPhantom9288

"""
    print(header)

class PhishingDetector:
    def __init__(self):
        # Suspicious TLDs commonly used in phishing
        self.suspicious_tlds = {
            'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'site',
            'online', 'webcam', 'work', 'tech', 'space', 'website', 'info'
        }
        
        # Common phishing keywords
        self.phishing_keywords = {
            'login', 'signin', 'verify', 'account', 'security', 'update',
            'confirm', 'banking', 'paypal', 'amazon', 'ebay', 'facebook',
            'google', 'apple', 'microsoft', 'secure', 'validation',
            'authentication', 'password', 'credentials'
        }
        
        # Known URL shorteners
        self.url_shorteners = {
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'shorte.st', 'bc.vc', 'bit.do', 'cli.gs',
            'cutt.ly', 'git.io', 'po.st', 'q.gs', 's2r.co', 's.id', 'soo.gd',
            'tiny.cc', 'urlzs.com', 'v.gd', 'x.co', 'yep.it', 'zip.net'
        }
        
        # Suspicious special characters
        self.suspicious_chars = ['@', '//', '--', '__', '..']
    
    def extract_url_features(self, url: str) -> Dict:
        """Extract all relevant features from URL"""
        features = {}
        
        # Parse URL components
        parsed_url = urllib.parse.urlparse(url)
        extracted = tldextract.extract(url)
        
        features['url'] = url
        features['has_https'] = parsed_url.scheme == 'https'
        features['domain'] = f"{extracted.domain}.{extracted.suffix}"
        features['subdomain'] = extracted.subdomain
        features['subdomain_depth'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
        features['has_ip'] = self._contains_ip(parsed_url.netloc)
        features['tld'] = extracted.suffix
        features['is_suspicious_tld'] = extracted.suffix in self.suspicious_tlds
        features['path_length'] = len(parsed_url.path)
        features['query_length'] = len(parsed_url.query)
        features['special_char_count'] = self._count_special_chars(url)
        features['digit_ratio'] = self._calculate_digit_ratio(parsed_url.netloc)
        features['contains_keyword_bait'] = self._contains_keyword_bait(url)
        features['is_shortener'] = self._is_url_shortener(parsed_url.netloc)
        features['has_suspicious_chars'] = any(char in url for char in self.suspicious_chars)
        
        return features
    
    def _contains_ip(self, netloc: str) -> bool:
        """Check if URL contains IP address instead of domain"""
        ip_patterns = [
            r'\d+\.\d+\.\d+\.\d+',  # IPv4
            r'\[[0-9a-fA-F:]+\]'     # IPv6
        ]
        return any(re.search(pattern, netloc) for pattern in ip_patterns)
    
    def _count_special_chars(self, url: str) -> int:
        """Count special characters in URL"""
        special_chars = r'[~!@#$%^&*()_+{}|:"<>?`\-=[\]\\;\',./]'
        return len(re.findall(special_chars, url))
    
    def _calculate_digit_ratio(self, netloc: str) -> float:
        """Calculate ratio of digits in domain name"""
        if not netloc:
            return 0.0
        digits = sum(1 for char in netloc if char.isdigit())
        return digits / len(netloc)
    
    def _contains_keyword_bait(self, url: str) -> bool:
        """Check if URL contains phishing bait keywords"""
        url_lower = url.lower()
        return any(keyword in url_lower for keyword in self.phishing_keywords)
    
    def _is_url_shortener(self, netloc: str) -> bool:
        """Check if URL uses known shortener service"""
        return netloc in self.url_shorteners
    
    def calculate_risk_score(self, features: Dict) -> Tuple[float, List[str]]:
        """Calculate risk score based on features"""
        score = 0
        reasons = []
        
        # HTTPS (positive factor)
        if not features['has_https']:
            score += 15
            reasons.append("Uses HTTP instead of HTTPS")
        
        # Subdomain depth
        if features['subdomain_depth'] > 2:
            score += 10 + (features['subdomain_depth'] - 2) * 5
            reasons.append(f"Deep subdomain nesting ({features['subdomain_depth']} levels)")
        
        # IP address in URL
        if features['has_ip']:
            score += 25
            reasons.append("Contains IP address instead of domain name")
        
        # Suspicious TLD
        if features['is_suspicious_tld']:
            score += 20
            reasons.append(f"Suspicious TLD: {features['tld']}")
        
        # Special characters
        if features['special_char_count'] > 5:
            score += min(20, features['special_char_count'] * 2)
            reasons.append(f"High number of special characters ({features['special_char_count']})")
        
        # Digit ratio
        if features['digit_ratio'] > 0.3:
            score += 15
            reasons.append(f"High digit ratio in domain ({features['digit_ratio']:.2f})")
        
        # Keyword bait
        if features['contains_keyword_bait']:
            score += 20
            reasons.append("Contains known phishing bait keywords")
        
        # URL shortener
        if features['is_shortener']:
            score += 25
            reasons.append("Uses URL shortening service")
        
        # Suspicious characters
        if features['has_suspicious_chars']:
            score += 15
            reasons.append("Contains suspicious character patterns")
        
        # Path and query length
        total_length = features['path_length'] + features['query_length']
        if total_length > 100:
            score += min(20, (total_length - 100) // 10)
            reasons.append(f"Long URL path/query ({total_length} characters)")
        
        return min(100, score), reasons
    
    def classify_url(self, score: float) -> str:
        """Classify URL based on risk score"""
        if score < 30:
            return "Likely Legit"
        elif score < 70:
            return "Suspicious"
        else:
            return "Likely Phishing"
    
    def analyze_url(self, url: str) -> Dict:
        """Complete analysis of a URL"""
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        features = self.extract_url_features(url)
        score, reasons = self.calculate_risk_score(features)
        classification = self.classify_url(score)
        
        return {
            'url': url,
            'features': features,
            'risk_score': score,
            'classification': classification,
            'reasons': reasons
        }
    
    def print_analysis(self, analysis: Dict):
        """Print analysis results in readable format"""
        print(f"\n{'='*60}")
        print(f"URL ANALYSIS REPORT")
        print(f"{'='*60}")
        print(f"URL: {analysis['url']}")
        print(f"Risk Score: {analysis['risk_score']}/100")
        print(f"Classification: {analysis['classification']}")
        print(f"\nFeature Analysis:")
        print(f"  - HTTPS: {'Yes' if analysis['features']['has_https'] else 'No'}")
        print(f"  - Domain: {analysis['features']['domain']}")
        print(f"  - Subdomains: {analysis['features']['subdomain'] or 'None'}")
        print(f"  - Subdomain depth: {analysis['features']['subdomain_depth']}")
        print(f"  - Contains IP: {'Yes' if analysis['features']['has_ip'] else 'No'}")
        print(f"  - TLD: {analysis['features']['tld']}")
        print(f"  - Suspicious TLD: {'Yes' if analysis['features']['is_suspicious_tld'] else 'No'}")
        print(f"  - Special chars: {analysis['features']['special_char_count']}")
        print(f"  - Digit ratio: {analysis['features']['digit_ratio']:.3f}")
        print(f"  - Contains bait: {'Yes' if analysis['features']['contains_keyword_bait'] else 'No'}")
        print(f"  - URL shortener: {'Yes' if analysis['features']['is_shortener'] else 'No'}")
        
        if analysis['reasons']:
            print(f"\nRisk Factors:")
            for reason in analysis['reasons']:
                print(f"  - {reason}")
        else:
            print(f"\nNo significant risk factors detected.")
        
        print(f"{'='*60}")

def main():
    parser = argparse.ArgumentParser(description='Phishing URL Detection Tool')
    parser.add_argument('url', nargs='?', help='URL to analyze')
    parser.add_argument('-f', '--file', help='File containing URLs to analyze (one per line)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (no header)')
    
    args = parser.parse_args()
    
    # Show header unless in quiet mode
    if not args.quiet:
        display_header()
    
    detector = PhishingDetector()
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            results = []
            for url in urls:
                analysis = detector.analyze_url(url)
                results.append(analysis)
                if args.verbose:
                    detector.print_analysis(analysis)
            
            # Summary
            legit_count = sum(1 for r in results if r['classification'] == 'Likely Legit')
            suspicious_count = sum(1 for r in results if r['classification'] == 'Suspicious')
            phishing_count = sum(1 for r in results if r['classification'] == 'Likely Phishing')
            
            print(f"\nSummary for {len(results)} URLs:")
            print(f"Likely Legit: {legit_count}")
            print(f"Suspicious: {suspicious_count}")
            print(f"Likely Phishing: {phishing_count}")
            
        except FileNotFoundError:
            print(f"Error: File {args.file} not found.")
    
    elif args.url:
        analysis = detector.analyze_url(args.url)
        detector.print_analysis(analysis)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()