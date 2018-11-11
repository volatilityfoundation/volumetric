# Introduction

Volumetric is a web-based GUI for the volatility3 library.

# Dependencies

Volumetric relies upon the following:

* npm (for webcomponents)
* &gt;=cherrypy-10  (for serving the pages)
* volatility3

# Installation

## Install Cherrypy

To install cherrypy locally, run:

pip3 install --user --upgrade cherrypy

## Install webcomponent dependencies

Then from the top level directory run:

npm install

# Running the server

From the top level directory

python3 vol.py
