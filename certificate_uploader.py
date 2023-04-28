import os
import re
from pathlib import Path

import requests
from dotenv import load_dotenv
from loguru import logger

from status_codes import (
    CERTIFICATE_ADDED_SUCCESSFULLY,
    CERTIFICATE_COULD_NOT_BE_GENERATED,
    CERTIFICATE_NOT_FOUND,
    CERTIFICATE_UPDATED_SUCCESSFULLY,
)

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

status_messages = {
    "update": {
        CERTIFICATE_NOT_FOUND: f"Certificate with name '{CERTIFICATE_NAME}' does not exist yet.",
        CERTIFICATE_UPDATED_SUCCESSFULLY: f"Successfully updated certificate with name '{CERTIFICATE_NAME}'.",
    },
    "add": {
        CERTIFICATE_COULD_NOT_BE_GENERATED: f"Certificate with name '{CERTIFICATE_NAME}' could not be generated. Did you pass the correct certificate path?",
        CERTIFICATE_ADDED_SUCCESSFULLY: f"Successfully added certificate with name '{CERTIFICATE_NAME}'.",
    },
}

cert_path = Path(f"{CERTIFICATE_PATH}")
cert_file = {
    "file": (cert_path.name, cert_path.read_text(), "text/plain"),
}


def check_firewall_response_return_status_code(
    update_or_add: str, response: requests.Response
) -> int:
    """Check the response from the firewall API, log appropriate messages based on the
    response, and return the status code.

    This function extracts the authentication status and status code from the firewall
    API's response. If the authentication status indicates a failure, it logs an error
    message. If a status code is present, it logs a message based on the action
    (update or add) and the status code. If no status code is found, it logs a warning.

    Args:
        update_or_add: The action performed on the certificate ("update" or "add").
        response: The Response object returned by the requests library after
        sending a request to the firewall API.

    Returns:
        The status code returned by the firewall API, or -1 if authentication failed or
        no status code was found.
    """

    # Parse the response and extract ...
    # ... the authentication status
    authentication_status_pattern = r"<status>Authentication (.*)</status>"
    match = re.search(authentication_status_pattern, response.text)
    if match:
        authentication_status = match.group(1)
        if authentication_status == "Failure":
            logger.error(
                "Could not authenticate with provided credentials. Please update admin "
                "username or password."
            )
            return -1

    # ... the status code
    status_code_pattern = r'<Status code="(\d+)">'
    match = re.search(status_code_pattern, response.text)

    if match:
        status_code = int(match.group(1))

        log_message = status_messages.get(update_or_add, {}).get(status_code)
        log_level = (
            logger.error
            if (update_or_add, status_code)
            == ("add", CERTIFICATE_COULD_NOT_BE_GENERATED)
            else logger.info
        )
        log_level(log_message) if log_message else logger.warning(
            f"Unexpected status_code ({status_code}) encountered."
        )
    else:
        logger.warning(f"No status code found: {response.text}.")
        status_code = -1
    return status_code


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

    status_code = check_firewall_response_return_status_code(
        update_or_add=update_or_add, response=response
    )

    return status_code


if __name__ == "__main__":
    # Update the certificate with given name on the firewall
    status_code = upload_certificate("update")

    # If the certificate name is not defined yet, add it
    if status_code == CERTIFICATE_NOT_FOUND:
        status_code = upload_certificate("add")
