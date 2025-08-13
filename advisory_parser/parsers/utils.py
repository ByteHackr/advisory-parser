# Copyright (c) 2017 Red Hat, Inc.
# Author: Martin Prpič,, Red Hat Product Security
# License: LGPLv3+

import re
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen, Request

from bs4 import BeautifulSoup

from advisory_parser.exceptions import AdvisoryParserGetContentException

# Enhanced CVE regex with validation and performance optimization
CVE_REGEX = re.compile(r"CVE-(?:19[789]\d|20[0-9]\d)-\d{4,}", re.IGNORECASE)

# Common false positive patterns to filter out
CVE_FALSE_POSITIVES = re.compile(r"CVE-(?:0000|9999)-\d+|CVE-\d{4}-(?:0000|9999)", re.IGNORECASE)


def get_request(url, max_retries=3, timeout=30):
    """
    Fetch URL content with timeout and retry logic for improved reliability.
    
    :param url: URL to fetch
    :param max_retries: Maximum number of retry attempts
    :param timeout: Request timeout in seconds
    :return: Response content
    """
    user_agent = (
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7"
    )
    headers = {"User-Agent": user_agent}
    
    for attempt in range(max_retries + 1):
        try:
            request = Request(url, None, headers)
            res = urlopen(request, timeout=timeout)
            return res.read()
        except HTTPError as e:
            if attempt == max_retries:
                error_msg = "Failed to GET with status code: {} after {} retries".format(e.code, max_retries)
                raise AdvisoryParserGetContentException(error_msg)
            # Don't retry on client errors (4xx), only server errors (5xx)
            if 400 <= e.code < 500:
                error_msg = "Failed to GET with status code: {}".format(e.code)
                raise AdvisoryParserGetContentException(error_msg)
            # Exponential backoff for server errors
            time.sleep(2 ** attempt)
        except (URLError, OSError) as e:
            if attempt == max_retries:
                error_msg = "Failed to establish connection: {} after {} retries".format(e.reason, max_retries)
                raise AdvisoryParserGetContentException(error_msg)
            # Exponential backoff for connection issues
            time.sleep(2 ** attempt)
        except ValueError:
            raise AdvisoryParserGetContentException("Invalid URL specified.")


def get_text_from_url(url):
    html = get_request(url)
    soup = BeautifulSoup(html, "html.parser")

    # Remove script and style tags and their contents
    for script in soup(["script", "style"]):
        script.decompose()

    text = soup.get_text()

    # Filter out blank lines and leading/trailing spaces
    text = "\n".join(line.strip() for line in text.splitlines() if line)

    return text


def find_tag_by_text(url, tag, text):
    html = get_request(url)
    soup = BeautifulSoup(html, "html.parser")
    return soup.find(tag, text=text)


def find_tag_by_id(url, tag, tag_id):
    html = get_request(url)
    soup = BeautifulSoup(html, "html.parser")
    return soup.findAll(tag, id=tag_id)


def extract_and_validate_cves(text):
    """
    Extract and validate CVE identifiers from text with enhanced filtering.
    
    :param text: Text to search for CVEs
    :return: List of validated, unique CVE identifiers
    """
    if not text:
        return []
    
    # Find all potential CVE matches
    potential_cves = CVE_REGEX.findall(text)
    
    # Filter out false positives and normalize
    valid_cves = []
    for cve in potential_cves:
        cve = cve.upper()  # Normalize to uppercase
        if not CVE_FALSE_POSITIVES.match(cve):
            # Additional validation: year should be reasonable
            year = int(cve.split('-')[1])
            if 1999 <= year <= 2030:  # Reasonable CVE year range
                valid_cves.append(cve)
    
    # Return unique CVEs while preserving order
    return list(dict.fromkeys(valid_cves))
