<<<<<<< HEAD
# ChatSphere
This application allows users to send and receive encrypted messages, including the option to upload images. It features a user-friendly interface for managing conversations and easily accessing message details.

# Encrypted Messaging Application

This is a secure messaging application built with Flask that enables users to send and receive encrypted messages, along with the ability to upload images. The app leverages RSA and AES encryption for secure communication.

## Features

- User authentication with signup and login functionality
- Send and receive encrypted messages
- Option to upload images along with messages
- View received messages in an organized inbox
- Delete messages as needed

## Technologies Used

- **Flask**: Web framework for building the application
- **Flask-SQLAlchemy**: ORM for database interactions
- **Flask-Login**: User session management
- **Cryptography**: For implementing RSA and AES encryption
- **SQLite**: Database for storing user and message data
- **Bootstrap**: For responsive front-end design

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/ravirajbabasomane202/ChatSphere.git
   cd ChatSphere
2. Run this commands:
   ```bash
   pip install -r requirements.txt
   flask db init
   flask db migrate -m "Initial migration."
   flask db upgrade
   python app.py
=======
# Secure_Communication_System
- Created a Flask web application that allows users to securely send messages using cryptography and steganography. 
- The system encrypts the message and hides it inside an image to protect the content from unauthorized access during 
  transmission.
- A security-focused application designed to protect digital communication by integrating encryption algorithms with steganography techniques.
- It ensures that the message is not only encrypted but also hidden inside another medium, adding a dual layer of protection.

  **Key Feature**

- Text Encryption & Decryption using standard cryptographic algorithms

- Image-based Steganography to hide encrypted messages

- Dual Layer Security (Encryption + Hiding)

- User-friendly Interface

- Fast, Reliable & Lightweight

- Secure Message Transmission

  **Technologies Used**
** Frontend

HTML

CSS

JavaScript

** Backend (if present)

Python / Java 

** Security Algorithms

Cryptography (Mention the exact algorithm: AES / RSA / Caesar Cipher / Custom)

Steganography (LSB Technique, etc.)
>>>>>>> df75514e39b7b1bbefe270e0e2cad135e8dcd1cd
