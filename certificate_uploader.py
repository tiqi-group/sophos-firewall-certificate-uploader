import os
import re
from pathlib import Path

import requests
from dotenv import load_dotenv
from loguru import logger

# Load environment variables from the .env file
load_dotenv()

# Read firewall-specific information from environment variables
FIREWALL_API_ADMIN = os.getenv("FIREWALL_API_ADMIN")
FIREWALL_API_ADMIN_PWD = os.getenv("FIREWALL_API_ADMIN_PWD")
FIREWALL_DOMAIN_AND_PORT = os.getenv("FIREWALL_DOMAIN_AND_PORT")

# Read certificate-specific information from environment variables
CERTIFICATE_PATH = os.getenv("CERTIFICATE_PATH")
CERTIFICATE_NAME = os.getenv("CERTIFICATE_NAME")
CERTIFICATE_PWD = os.getenv("CERTIFICATE_PWD")

# Evaluates to `True` if set to True (case-insensitive) or 1, else False
VERIFY_SSL_CERTIFICATE = os.getenv(
    "VERIFY_SSL_CERTIFICATE", default="False"
).lower() in (
    "true",
    "1",
)

# Construct the firewall API URL
FIREWALL_API_URL = f"https://{FIREWALL_DOMAIN_AND_PORT}/webconsole/APIController"
CERTIFICATE_NOT_FOUND = 500

cert_path = Path(f"{CERTIFICATE_PATH}")
cert_file = {
    "file": (cert_path.name, cert_path.read_text(), "text/plain"),
}


def upload_certificate(update_or_add: str) -> int:
    """Uploads or updates a certificate to the firewall by sending a POST request to the
    firewall API.

    Args:
        update_or_add: The action to perform on the certificate ("update" or "add").

    Returns:
        The status code returned by the firewall API.
    """

    update_certificate_xml = f"""
    <Request>
        <Login>
            <Username>{FIREWALL_API_ADMIN}</Username>
            <Password>{FIREWALL_API_ADMIN_PWD}</Password>
        </Login>
        <Set operation='{update_or_add}'>
            <Certificate>
                <Action>UploadCertificate</Action>
                <Name>{CERTIFICATE_NAME}</Name>
                <Password>{CERTIFICATE_PWD if CERTIFICATE_PWD is not None else ""}</Password>
                <CertificateFormat>pem</CertificateFormat>
                <CertificateFile>{cert_path.name}</CertificateFile>
                <PrivateKeyFile></PrivateKeyFile>
            </Certificate>
        </Set>
    </Request>
    """

    # Send a POST request to the firewall API with the XML string and certificate file
    data = {"reqxml": update_certificate_xml}
    response = requests.post(
        FIREWALL_API_URL,
        data=data,
        files=cert_file,
        verify=VERIFY_SSL_CERTIFICATE,
    )
    logger.debug(response.text)

    # Parse the response and extract the status code
    pattern = r'<Status code="(\d+)">'
    match = re.search(pattern, response.text)

    if match:
        status_code = int(match.group(1))
    else:
        raise Exception("API call did not return a response!")

    return status_code


if __name__ == "__main__":
    # Update the certificate with given name on the firewall
    status_code = upload_certificate("update")

    # If the certificate name is not defined yet, add it
    if status_code == CERTIFICATE_NOT_FOUND:
        status_code = upload_certificate("add")
