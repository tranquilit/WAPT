"""Implementation of ISesNework in Python."""

import logging
import logging.handlers

import pythoncom

import time

from win32com.server.policy import DesignatedWrapPolicy
from win32com.client import Dispatch

## from EventSys.h
PROGID_EventSystem = "EventSystem.EventSystem"
PROGID_EventSubscription = "EventSystem.EventSubscription"

# sens values for the events, this events contain the uuid of the
# event, the name of the event to be used as well as the method name
# of the method in the ISesNetwork interface that will be executed for
# the event.


service_logger = logging.getLogger()

SUBSCRIPTION_NETALIVE = ('{cd1dcbd6-a14d-4823-a0d2-8473afde360f}',
                         'UbuntuOne Network Alive',
                         'ConnectionMade')

SUBSCRIPTION_NETALIVE_NOQOC = ('{a82f0e80-1305-400c-ba56-375ae04264a1}',
                               'UbuntuOne Net Alive No Info',
                               'ConnectionMadeNoQOCInfo')

SUBSCRIPTION_NETLOST = ('{45233130-b6c3-44fb-a6af-487c47cee611}',
                        'UbuntuOne Network Lost',
                        'ConnectionLost')

SUBSCRIPTION_REACH = ('{4c6b2afa-3235-4185-8558-57a7a922ac7b}',
                       'UbuntuOne Network Reach',
                       'ConnectionMade')

SUBSCRIPTION_REACH_NOQOC = ('{db62fa23-4c3e-47a3-aef2-b843016177cf}',
                            'UbuntuOne Network Reach No Info',
                            'ConnectionMadeNoQOCInfo')

SUBSCRIPTION_REACH_NOQOC2 = ('{d4d8097a-60c6-440d-a6da-918b619ae4b7}',
                             'UbuntuOne Network Reach No Info 2',
                             'ConnectionMadeNoQOCInfo')

SUBSCRIPTIONS = [SUBSCRIPTION_NETALIVE,
                 SUBSCRIPTION_NETALIVE_NOQOC,
                 SUBSCRIPTION_NETLOST,
                 SUBSCRIPTION_REACH,
                 SUBSCRIPTION_REACH_NOQOC,
                 SUBSCRIPTION_REACH_NOQOC2 ]

SENSGUID_EVENTCLASS_NETWORK = '{d5978620-5b9f-11d1-8dd2-00aa004abd5e}'
SENSGUID_PUBLISHER = "{5fee1bd6-5b9b-11d1-8dd2-00aa004abd5e}"

# uuid of the implemented com interface
IID_ISesNetwork = '{d597bab1-5b9f-11d1-8dd2-00aa004abd5e}'


class NetworkManager(DesignatedWrapPolicy):
    """Implement ISesNetwork to know about the network status."""

    _com_interfaces_ = [IID_ISesNetwork]
    _public_methods_ = ['ConnectionMade',
                        'ConnectionMadeNoQOCInfo',
                        'ConnectionLost']
    _reg_clsid_ = '{41B032DA-86B5-4907-A7F7-958E59333010}'
    _reg_progid_ = "UbuntuOne.NetworkManager"

    def __init__(self, connected_cb, disconnected_cb):
        self._wrap_(self)
        self.connected_cb = connected_cb
        self.disconnected_cb = disconnected_cb

    def ConnectionMade(self, *args):
        """Tell that the connection is up again."""
        service_logger.info('Connection was made.')
        self.connected_cb()

    def ConnectionMadeNoQOCInfo(self, *args):
        """Tell that the connection is up again."""
        service_logger.info('Connection was made no info.')
        self.connected_cb()

    def ConnectionLost(self, *args):
        """Tell the connection was lost."""
        service_logger.info('Connection was lost.')
        self.disconnected_cb()

    def register(self):
        """Register to listen to network events."""
        # call the CoInitialize to allow the registration to run in an other
        # thread
        pythoncom.CoInitialize()
        # interface to be used by com
        manager_interface = pythoncom.WrapObject(self)
        event_system = Dispatch(PROGID_EventSystem)
        # register to listent to each of the events to make sure that
        # the code will work on all platforms.
        for current_event in SUBSCRIPTIONS:
            # create an event subscription and add it to the event
            # service
            event_subscription = Dispatch(PROGID_EventSubscription)
            event_subscription.EventClassId = SENSGUID_EVENTCLASS_NETWORK
            event_subscription.PublisherID = SENSGUID_PUBLISHER
            event_subscription.SubscriptionID = current_event[0]
            event_subscription.SubscriptionName = current_event[1]
            event_subscription.MethodName = current_event[2]
            event_subscription.SubscriberInterface = manager_interface
            event_subscription.PerUser = True
            # store the event
            try:
                event_system.Store(PROGID_EventSubscription,
                                   event_subscription)
            except pythoncom.com_error as e:
                service_logger.error(
                    'Error registering to event %s', current_event[1])

        pythoncom.PumpMessages()

if __name__ == '__main__':
    from threading import Thread

    def connected():
        print 'Connected'

    def disconnected():
        print 'Disconnected'

    manager = NetworkManager(connected, disconnected)
    p = Thread(target=manager.register)
    p.start()

    while True:
        print('sleeping')
        time.sleep(1)
