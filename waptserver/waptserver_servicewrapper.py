### Run Python scripts as a service example (ryrobes.com)
### Usage : python aservice.py install (or / then start, stop, remove)

import win32service
import win32serviceutil
import win32api
import win32con
import win32event
import win32evtlogutil
import os, sys, string, time
import logging

from rocket import Rocket


class aservice(win32serviceutil.ServiceFramework):

    _svc_name_ = "WAPTServer"
    _svc_display_name_ = "WAPT Server"
    _svc_description_ = "WAPTServer for configuring and deploying wapt packages on a network"
    _svc_deps_ = ["WAPTMongodb"]
    server = None

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):

        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.server.stop()

    def SvcDoRun(self):
        import servicemanager
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,servicemanager.PYS_SERVICE_STARTED,(self._svc_name_, ''))

        from waptserver import app,waptserver_port,log_directory,logger
        hdlr = logging.FileHandler(os.path.join(log_directory,'waptserver.log'))
        hdlr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        logger.addHandler(hdlr)
        logger.info('waptserver starting')

        self.server = Rocket(('0.0.0.0', waptserver_port), 'wsgi', {"wsgi_app":app})
        try:
            self.server.start()
        except KeyboardInterrupt:
            self.server.stop()


def ctrlHandler(ctrlType):
    return True

if __name__ == '__main__':
    win32api.SetConsoleCtrlHandler(ctrlHandler, True)
    win32serviceutil.HandleCommandLine(aservice)
