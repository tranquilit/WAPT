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

    _svc_name_ = "WAPTService"
    _svc_display_name_ = "WAPT Service"
    _svc_description_ = "WAPTService for configuring local machine"

    server = None

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.server.stop()

    def SvcDoRun(self):
        from waptservice import log_directory
        file = open(os.path.join(log_directory,'waptservice.log'), 'a')
        try:
            import servicemanager
            servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,servicemanager.PYS_SERVICE_STARTED,(self._svc_name_, ''))

            from waptservice import app,waptservice_port,log_directory,logger

            logging.basicConfig(filename=os.path.join(log_directory,'waptservice.log'),format='%(asctime)s %(levelname)s %(message)s')
            logger.info('waptservice starting')


            self.server = Rocket(('0.0.0.0', waptservice_port), 'wsgi', {"wsgi_app":app})
        except Exception as e:
            file.writelines("Exeption: %s" %e)
        finally:
            file.close()
        try:
            self.server.start()
        except KeyboardInterrupt:
            self.server.stop()


def ctrlHandler(ctrlType):
    return True

if __name__ == '__main__':
    win32api.SetConsoleCtrlHandler(ctrlHandler, True)
    win32serviceutil.HandleCommandLine(aservice)

