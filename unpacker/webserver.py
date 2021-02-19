def run_flask_server(x_axis, y_axis, selected, recording_name):
    from flask import Flask, render_template, url_for, copy_current_request_context, request
    from flask_socketio import SocketIO, emit
    from time import sleep
    from threading import Thread, Event
    from multiprocessing import Process
    from ghidra_integration import do_transition_to_ghidra

    global server
    app = Flask(__name__)
    app.use_reloader = False
    app.debug = False
    app.config['SECRET_KEY'] = 'secret!'
    app.config['DEBUG'] = False
    app.logger.disabled = True
    import logging
    log = logging.getLogger('werkzeug')
    log.disabled = True
    #turn the flask app into a socketio app
    socketio = SocketIO(app, async_mode=None, logger=False, debug=False, use_reloader=False)


    @app.route('/graph.js')
    def graph():
        return render_template('graph.js', chart_x=x_axis,chart_y=y_axis)

    @app.route("/")
    def webpage():
        return render_template('graph.html')
    
    global thread
    global thread_stop_event
    thread = Thread()
    thread_stop_event = Event()

    def emitEvents():
        last_len_x = len(x_axis)
        while not thread_stop_event.isSet():
            try:
                if last_len_x < len(x_axis) and last_len_x < len(y_axis):
                    arr_to_emit = min(len(x_axis), len(y_axis))
                    list_to_emit = [{'x': x_axis[i],
                                    'y': y_axis[i]} 
                                    for i in range(last_len_x, arr_to_emit)]
                    socketio.emit('addnodes', {'list': list_to_emit},
                                            namespace='/test')
                    last_len_x = arr_to_emit
                socketio.sleep(0.1)
            except:
                return

    global last_process 
    last_process = None

    @socketio.on('selection', namespace='/test')
    def selection(value):
        global last_process
        if last_process is not None:
            last_process.join(timeout=0)
            if last_process.is_alive():
                return
            last_process = None
        new_process = Process(target=do_transition_to_ghidra, args=(value, recording_name))
        new_process.start()
        last_process = new_process
    
    @socketio.on('connect', namespace='/test')
    def test_connect():
        # need visibility of the global thread object
        global thread
        print('Client connected')
        #Start the random number generator thread only if the thread has not been started before.
        if not thread.isAlive():
            print("Starting Thread")
            thread_stop_event.clear()
            thread = socketio.start_background_task(emitEvents)

    @socketio.on('disconnect', namespace='/test')
    def test_disconnect():
        print('Client disconnected')
        thread_stop_event.set()

    socketio.run(app,host='0.0.0.0',port=8888, debug=True, use_reloader=False)