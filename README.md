# LAN Messenger
A messenger app to connect to users over the same network.

## Features
- **Contact List**: Every user on the network automatically has everyone else's contact
- **Group Chats**: Users can create and manage groups with options to add and remove members
- **Media Support**: Images, videos, and audio files can be sent in chats
- **Profile Customisation**: Users can change their profile picture, status and toggle light/dark mode

## Requirements
Make sure to install the following dependencies:
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

## Known Issues
- When a user is kicked from a group, the group is not removed for them until they reload the site
- The 'New' notification should disappear when the contact is clicked on, not once it's clicked out of

## Planned Features
- [ ] Public-Key E2EE
- [ ] Client-side File Compression
