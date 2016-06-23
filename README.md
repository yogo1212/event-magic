# event-magic

## Brief

What is it?

- library for linux. Probably not hard to port to other POSIX-like platforms.
- links againt libevent and SSL
- tab indented
- event-oriented

What's in it?

- SSL-connection-stuff you might not be using
- a MQTT-client-implementation you might not like
- a websocket-client-implementation you might not need
- base64

If you think that's great.. Great!
If you think there's something wrong with it - tell me!
Any questions? Just ask!
-----> Feel free to steal my code <-----
You can then still add my name in the source if you're nice - or not (go figure out which part of the previous sentence that refers to).

## Dependencies

This will not work without an SSL-library or libevent.
Not tested with the latest release of libevent. It should work with 2.1.5beta, though.
I test with the latest git. Because i like being reckless.

## Why bother?

Have you ever had a look at the HTTPS-client sample from libevent?
I had - and i thought 'Isn't the example supposed to convince me it's going to be easy? There must a way to build a framework that allows to write this in just a few lines!'.

Turns out i haven't found a way to do just that. And my client doesn't seem to work in the same cases as the libevent-example.
But at least it's a lot shorter and most of the code is about parsing user-input and less about actual logic for dealing with HTTP over SSL.

Have you tried using MQTT through libevent? Or websockets? Chances are that: No, you haven't and your fine. The blocking way of life is valid too. Just ignore this then.

## The usual stuff

Hi, i like food. And women. And men too - generally speaking. I like them all. Only in different ways.

This is a personal project. If you want to add something or recommend a change drop a message or open a pull request.

Ohh.. And: The lists of downsides here might not be complete. Please tell me if you think they are.

# SSL

Sadly, SSL isn't that well integrated into bufferevents. For instance, reconnecting the same bufferevent after disconnect probably wont work (at least they didn't the last time i checked).
Maybe that will change but right now it's hard to use. I've seen me and my colleagues writing the same code over and over.

If you feel a similar way and really hope to see all your problems solved - make sure i don't get your hopes up and then disappoint you:

## Downsides

- has global state (meaning you'll have to call `lew_ssl_lib_init` and `lew_ssl_lib_cleanup`)
- only wraps SSL and libevent calls; meaning that much of the ugliness will only be hidden

## Essence

So what does it give you? The design is based around the idea to have a SSL-factory:

Initialise the factory with hostname and port.
You can give it a callback in which you can give the SSL_ctx special treatments.
After you have configured the factory you can call `lew_ssl_connect(factory)` and get a bufferevent.
Take it - it's yours. Call it again to have another. You are responsible for cleaning them up and they no longer need the factory.

Also, you can choose NOT to use SSL - that way you can use the same interface for having both.

# MQTT

Looking for a MQTT-client-implementation running on libevent?

Try this - if you dare:
`LD_LIBRARY_PATH=libout/ examplesout/mqtt_sub -t '/#' -t '+' -s test.mosquitto.org -p 1883 -a mosquitto.org.crt -r -v -l`

## Why this?

The most advanced MQTT-library i know is libmosquitto and it's fine for the most part. I haven't really looked for many others.
But i've really had trouble making mosquitto work with libevent :-(
It works - don't get me wrong - and i haven't really tried using it without libevent, so i won't claim it's bad.
My experience with it just wasn't that magical :-( Ohh, it's so sad  :\*

## Downsides

- Its author can't really think of any downsides. That's probably a bad thing.
- Or it means, he is tired.

# Websockets

You know? It's getting late and i still want to write some code.
