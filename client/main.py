#!/usr/bin/python

import websocket
import os

ws = None

def on_message(ws, message):
    os.system("say " + message)
    print message

def open_ws():
    ws = websocket.WebSocketApp("ws://localhost:8080", on_message = on_message, on_close = on_close)
    ws.run_forever()

def on_close(ws):
    print '### closed ###'
    open_ws()

if __name__ == "__main__":
    open_ws()
