from __future__ import print_function
import os.path
import re
import base64
import email
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def main():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = get_credentials()

    try:
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)
        messages_list = service.users().messages().list(userId='me', labelIds=None, q=None,
                                                        pageToken=None, maxResults=None, includeSpamTrash=None).execute().get('messages')
        for msg in messages_list:
            txt = service.users().messages().get(userId='me', id=msg['id'],
                                                 format=None, metadataHeaders=None).execute()
            payload = txt['payload']
            headers = payload['headers']
            sender = extract_sender(headers)
            if re.search("^Domo", sender):
                parts = payload.get('parts')
                if parts is not None:
                    parts = parts[0]
                    data = parts['body']['data']
                    decoded_data = decode_base64_data(data)
                    print(type(decoded_data))

    except HttpError as error:
        handle_api_error(error)


def get_credentials():
    creds = None
    token_file = 'token.json'

    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)

    if not creds or not creds.valid:
        creds = refresh_credentials(creds, token_file)

    save_credentials(creds, token_file)
    return creds


def refresh_credentials(creds, token_file):
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file(
            'credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
    return creds


def save_credentials(creds, token_file):
    with open(token_file, 'w') as token:
        token.write(creds.to_json())


def extract_sender(headers):
    for header in headers:
        if header['name'] == 'From':
            return header['value']
    return ''


def decode_base64_data(data):
    data = data.replace("-", "+").replace("_", "/")
    decoded_data = base64.b64decode(data)
    return data  # decoded_data


def handle_api_error(error):
    # TODO(developer) - Handle errors from Gmail API.
    print(f'An error occurred: {error}')


if __name__ == '__main__':
    main()
