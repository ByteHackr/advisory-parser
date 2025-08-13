# Copyright (c) 2019 Red Hat, Inc.
# Author: Martin Prpič, Red Hat Product Security
# License: LGPLv3+

from urllib.parse import urlparse
from .parsers import *
from .exceptions import AdvisoryParserUrlException


class Parser:
    """Parser for various project-specific advisory pages"""

    @classmethod
    def parse_from_url(cls, url):
        """
        Parses content from provided URL and returns a list of flaws containing all parsed data.

        :param url: URL to parse
        :return: Tuple of (List of Flaw objects, List of warning messages)
        """
        if not url:
            raise AdvisoryParserUrlException("No URL specified")
        
        # Validate and normalize URL
        url = cls._validate_and_normalize_url(url)

        if "chromereleases" in url:
            return parse_chrome_advisory(url)

        elif "wireshark.org" in url:
            pass

        elif "flash-player" in url:
            return parse_flash_advisory(url)

        elif "oracle.com" in url:
            return parse_mysql_advisory(url)

        elif "jenkins.io" in url:
            return parse_jenkins_advisory(url)

        elif "phpmyadmin" in url:
            pass

        else:
            raise AdvisoryParserUrlException("Could not find parser for: {}".format(url))
    
    @classmethod
    def _validate_and_normalize_url(cls, url):
        """
        Validate URL format and normalize for consistent parsing.
        
        :param url: Raw URL string
        :return: Normalized URL string
        :raises AdvisoryParserUrlException: If URL is invalid
        """
        if not url or not url.strip():
            raise AdvisoryParserUrlException("Empty URL provided")
            
        url = url.strip()
        
        # Check for basic URL structure
        if url in ['http://', 'https://'] or '://' in url and not url.startswith(('http://', 'https://')):
            raise AdvisoryParserUrlException("Invalid URL format: {}".format(url))
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            # Only add https if it looks like a domain
            if '.' not in url or url.startswith('.') or url.endswith('.'):
                raise AdvisoryParserUrlException("Invalid URL format: {}".format(url))
            url = 'https://' + url
        
        try:
            parsed = urlparse(url)
            if not parsed.netloc or parsed.netloc in ['', '.']:
                raise AdvisoryParserUrlException("Invalid URL format: {}".format(url))
        except Exception:
            raise AdvisoryParserUrlException("Malformed URL: {}".format(url))
        
        return url
