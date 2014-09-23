#!/usr/bin/env python

from flask import Flask, jsonify, request, render_template
import time, threading, random, webbrowser

app = Flask(__name__)

time_format = {
    'one': "%H:%M:%S",
    'best': "%a, %d %b %Y %H:%M:%S +0000",
    'other': "%a, %H:%M",
}

@app.route("/data", methods=['GET'])
def data():
    """Primary data source for AJAX/REST queries. Get's the server's current
    time two ways: as raw data, and as a formatted string. NB While other
    Python JSON emitters will directly encode arrays and other data types,
    Flask.jsonify() appears to require a dict. """

    fmt    = request.args.get('format', 'best')  # gets query parameter here; default 'best'

    now    = time.time()
    nowstr = time.strftime(time_format[fmt])

    info = { 'value':    now,
             'contents': "The time is now {} (format = '{}')".format(nowstr, fmt),
             'format':   fmt
            }
    return jsonify(info)

@app.route("/updated")
def updated():
    """Wait until something has changed, and report it. Python has *meh* support
    for threading, as witnessed by the umpteen solutions to this problem (e.g.
    Twisted, gevent, Stackless Python, etc). Here we use a simple check-sleep
    loop to wait for an update. app.config is handy place to stow global app
    data."""

    while not app.config['updated']:
        time.sleep(0.5)
    app.config['updated'] = False  # it'll be reported by return, so turn off signal
    return "changed!"

@app.route("/")
def main():

    return render_template("index.html")

def occasional_update(minsecs=5, maxsecs=25, first_time=False):
    """Simulate the server having occasional updates for the client. The first
    time it's run (presumably synchronously with the main program), it just
    kicks off an asynchronous Timer. Subsequent invocations (via Timer)
    acutally signal an update is ready."""

    app.config['updated'] = not first_time
    delay = random.randint(minsecs, maxsecs)
    threading.Timer(delay, occasional_update ).start()


if __name__ == "__main__":
    # start occasional update simulation
    occasional_update(first_time=True)

    # start server and web page pointing to it
    port = 5000 + random.randint(0, 999)
    url = "http://127.0.0.1:{}".format(port)
    wb = webbrowser.get(None)  # instead of None, can be "firefox" etc
    threading.Timer(1.25, lambda: wb.open(url) ).start()
    app.run(port=port, debug=False)