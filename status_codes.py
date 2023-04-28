import re

import requests
from loguru import logger

# Firewall API status codes
CERTIFICATE_UPDATED_SUCCESSFULLY = 200
CERTIFICATE_ADDED_SUCCESSFULLY = 200
CERTIFICATE_NOT_FOUND = 500
CERTIFICATE_COULD_NOT_BE_GENERATED = 500
CERTIFICATE_ALREADY_EXISTS = 502


def check_firewall_response_and_return_status_code(
    update_or_add: str, response: requests.Response, cert_name: str
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

    status_messages = {
        "update": {
            CERTIFICATE_NOT_FOUND: f"Certificate with name '{cert_name}' does not exist yet.",
            CERTIFICATE_UPDATED_SUCCESSFULLY: f"Successfully updated certificate with name '{cert_name}'.",
        },
        "add": {
            CERTIFICATE_COULD_NOT_BE_GENERATED: f"Certificate with name '{cert_name}' could not be generated. Did you pass the correct certificate path?",
            CERTIFICATE_ADDED_SUCCESSFULLY: f"Successfully added certificate with name '{cert_name}'.",
        },
    }

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
        if log_message:
            if (update_or_add, status_code) in [
                ("add", CERTIFICATE_COULD_NOT_BE_GENERATED)
            ]:
                logger.error(log_message)
            else:
                logger.info(log_message)
        else:
            logger.warning(f"Unexpected status_code ({status_code}) encountered.")

    else:
        logger.warning(f"No status code found: {response.text}.")
        status_code = -1
    return status_code
