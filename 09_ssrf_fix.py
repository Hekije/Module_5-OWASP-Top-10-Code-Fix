# OWASP A10:2021
# Server-Side Request Forgery (SSRF)
# Secure URL request example

import requests

from urllib.parse import urlparse


# Only these hosts may be contacted.
ALLOWED_HOSTS = {
    "api.example.com",
    "images.example.com"
}


def fetch_url(url):

    parsed_url = urlparse(url)

    # Only allow HTTPS
    if parsed_url.scheme != "https":
        raise ValueError(
            "Only HTTPS URLs are allowed."
        )

    hostname = parsed_url.hostname

    # Host must be specifically approved
    if hostname not in ALLOWED_HOSTS:
        raise ValueError(
            "The requested host is not allowed."
        )

    response = requests.get(
        url,
        timeout=5,
        allow_redirects=False
    )

    response.raise_for_status()

    return response.text


if __name__ == "__main__":

    url = input(
        "Enter an approved HTTPS URL: "
    )

    try:

        result = fetch_url(url)

        print(result)

    except requests.RequestException:

        print(
            "The remote request failed."
        )

    except ValueError as error:

        print(
            "Request rejected:",
            error
        )