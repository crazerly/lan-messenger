# LAN Messenger

A messenger app to connect users over the same network.

## Features

- Every user on the network automatically has everyone else's contact
- Users can create and manage groups with options to kick and add members
- Images, videos, and audio files can be sent in chats
- Users can change their profile picture, status and toggle light/dark mode
- All messages and files have end-to-end encryption

## Requirements

Install the following dependencies:

- `express`
- `cors`
- `bcryptjs`
- `multer`
- `socket.io`

## Setup

1. Clone the repository:

```bash
git clone https://github.com/yourusername/lan-messenger.git
cd lan-messenger
```

2. Install dependencies:

```bash
npm install express cors bcryptjs multer socket.io
```

3. Start the server:

```bash
node server.js
```

## How it works

The app has a simple structure between the server, client and database. Most functions follow a three-step process:

1. A user performs an action (e.g. updating their status or sending a message).
2. The server updates the corresponding data in the database (e.g. changes the user's status in the 'users' table).
3. The server broadcasts the update to all the connected clients.

## Examples

![](https://github.com/crazerly/lan-messenger/blob/main/imgs/contact_chat.png?raw=true)
_Contact chat_

![](https://github.com/crazerly/lan-messenger/blob/main/imgs/member_options.png?raw=true)
_Members chat with options_

![](https://github.com/crazerly/lan-messenger/blob/main/imgs/dark_mode.png?raw=true)
_Dark mode_

## Planned Features

- [ ] Client-side File Compression

