from __future__ import print_function
import os.path
import re
import base64
import email
import html2text
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from datetime import date
from datetime import datetime
from bs4 import BeautifulSoup


SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
billers = ['Ibanking.KE@sc.com',
           'receipts-kenya@bolt.eu', 'alerts.kenya@sc.com']
query = "newer_than:30d"
search_words = ["Amount", "Transfer Amount"]


def main():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = get_credentials()

    try:
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)
        messages_list = service.users().messages().list(userId='me', labelIds=None, q=query,
                                                        pageToken=None, maxResults=None, includeSpamTrash=None).execute().get('messages')
        for msg in messages_list:
            txt = service.users().messages().get(userId='me', id=msg['id'],
                                                 format=None, metadataHeaders=None).execute()
            payload = txt['payload']
            headers = payload['headers']
            sender = extract_sender(headers)
            marker1 = sender.find('<') + 1
            marker2 = sender.find('>')
            sender = sender[marker1:marker2]
            if sender in billers:
                if payload['mimeType'] == 'text/html':
                    message = decode_base64_data(payload['body']['data'])
                elif payload['mimeType'] == 'multipart/mixed':
                    parts = payload.get('parts')
                    parts = parts[0]
                    parts = parts['body']
                    if 'data' in parts.keys():
                        message = decode_base64_data(parts['data'])
                        # message = str(message).replace("<br/>", "")

                        transfer_amount = re.search(
                            r"Transfer Amount : (KES [\d,]+\.\d{2})", message)
                        if transfer_amount:
                            print("Transfer Amount:", transfer_amount.group(1))
                        else:
                            print("Transfer Amount not found.")

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
    # decoded_data = base64.urlsafe_b64decode(data).decode('UTF8')

    decoded_data = data.replace("-", "+").replace("_", "/")
    decoded_data = base64.b64decode(decoded_data)
    decoded_data = BeautifulSoup(decoded_data, "lxml")
    soup = BeautifulSoup(str(decoded_data), "html.parser")
    text = soup.get_text()
    return text


def handle_api_error(error):
    # TODO(developer) - Handle errors from Gmail API.
    print(f'An error occurred: {error}')


if __name__ == '__main__':
    main()
