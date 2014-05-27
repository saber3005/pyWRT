"""Paramiko Control Library for Atheros-based DD-WRT.

This module contains the basic functions for router
control without specific implementation details
"""

import functools
import logging
import re
import socket

import paramiko


logger = logging.getLogger(__name__)
logger.level = logging.INFO
logging.getLogger("paramiko.transport").level = logging.WARNING

# Define valid channels and their frequencies
GBAND = {
    "1": "2412",
    "2": "2417",
    "3": "2422",
    "4": "2427",
    "5": "2432",
    "6": "2437",
    "7": "2442",
    "8": "2447",
    "9": "2452",
    "10": "2457",
    "11": "2462",
}

ABAND = {
    "36": "5180",
    "40": "5200",
    "44": "5220",
    "48": "5240",
    "149": "5745",
    "153": "5765",
    "157": "5785",
    "161": "5805",
    "165": "5825",
}


class DDWRTError(Exception):
  pass


class SSIDError(DDWRTError):
  pass


def Setup(restart):
  """Decorator function to provide proper scope to Atheros instance methods.

  This decorator is responsible for initializing the ssh connection so that it
  can be passed to the decorated method without any extra boilerplate. It's
  also responsible for tearing down the connection after use, and can
  optionally run "rc restart" before teardown.

  "rc restart" reinitializes the router's firmware to take nvram changes into
  account. This is equivalent to a "Save" or "Apply Changes" function, though
  it is worth noting that it is only necessary for nvram changes.

  Args:
    restart: A boolean for running "rc restart" after the decorated method

  Returns:
    Wrapper: The resulting method with setup and teardown
  """
  def Wrapper(func):
    """A modified decorator function."""
    @functools.wraps(func)
    def Wrapped(self, *args, **kwargs):
      """The final returned version of the method being decorated."""
      # Retry the operation in case of failure
      for tries in reversed(xrange(self.tries)):
        try:
          # Set up ssh connection
          logger.debug("Setting up SSH connection to %s.", self.hostname)
          self.ssh.connect(hostname=self.hostname, port=self.port,
                           username=self.username, password=self.password,
                           pkey=self.key)

          # Call the function with this scope
          func(self, *args, **kwargs)

          # Apply and tear down ssh connection
          if restart:
            logger.debug("Applying Changes.")
            self.ssh.exec_command("rc restart")
          break
        except EOFError as e:
          _FailHandler("The Router's SSH server is not yet accepting "
                       "connections.", tries, e)
        except (paramiko.SSHException, socket.error) as e:
          _FailHandler(e.message, tries, e)
        finally:
          logger.debug("Closing SSH connection to %s.", self.hostname)
          self.ssh.close()
    # Pass original function so it can be called without setup/teardown
    # This is useful because it allows functions to be nested.
    Wrapped.nosetup = func
    return Wrapped
  return Wrapper


def _FailHandler(text, tries_left, e):
  if tries_left > 0:
    logger.warning(text + " %s Attempts Remaining.", tries_left)
  else:
    raise e


class Atheros(object):
  """A class to implement communication with an Atheros-based DD-WRT Router.

  Attributes:
    hostname: The IP address or URL of the device to be connected to.
    port: The port number the remote router is listening on for SSH connections.
    keyfile: The location of the file containing a private key
    password: The password to the ssh server or the private key
    tries: The number of times to attempt an action
  """

  def __init__(self, hostname, port=22, keyfile=None, password=None, tries=5):
    """The initialization function for the Atheros class.

    Args:
      hostname: A string representing an IP address or URL
      port: An int representing the sshd listen port
      keyfile: The location of the file containing a private key
      password: The password to the ssh server or the private key
      tries: The number of times to attempt an action
    """
    self.ssh = paramiko.SSHClient()
    self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    if keyfile:
      self.key = paramiko.RSAKey.from_private_key_file(keyfile)
    else:
      self.key = None

    self.hostname = hostname
    self.username = "root"
    self.password = password
    self.port = port
    self.tries = tries

  @Setup(restart=False)
  def ForwardTCP(self, ext_port, int_ip, int_port):
    """Forwards a TCP port through the router's NAT.

    Args:
      ext_port: The external port on the router
      int_ip: The internal IP address of the device
      int_port: The internal port which should receive connections
    """
    logger.info("Forwarding router port %s:%s to %s:%s.",
                self.hostname, ext_port, int_ip, int_port)
    self.ssh.exec_command("iptables -t nat -I PREROUTING -p tcp "
                          "-d $(nvram get wan_ipaddr) --dport %s -j DNAT "
                          "--to %s:%s" % (ext_port, int_ip, int_port))
    self.ssh.exec_command("iptables -I FORWARD -p tcp -d %s --dport %s "
                          "-j ACCEPT" % (int_ip, int_port))

  @Setup(restart=True)
  def Set2ghz(self, active):
    """Turns the 2GHz radio on or off."""
    if active:
      logger.info("Turning 2GHz Radio On for %s.", self.hostname)
      self.ssh.exec_command("nvram set ath0_net_mode=mixed")
      self.ssh.exec_command("nvram set ath0_gmode=1")
    else:
      logger.info("Turning 2GHz Radio Off for %s.", self.hostname)
      self.ssh.exec_command("nvram set ath0_net_mode=disabled")
      self.ssh.exec_command("nvram set ath0_gmode=-1")

  @Setup(restart=True)
  def Set5ghz(self, active):
    """Turns the 5GHz radio on or off."""
    if active:
      logger.info("Turning 5GHz Radio On for %s.", self.hostname)
      self.ssh.exec_command("nvram set ath1_net_mode=mixed")
      self.ssh.exec_command("nvram set ath1_gmode=1")
    else:
      logger.info("Turning 5GHz Radio Off for %s.", self.hostname)
      self.ssh.exec_command("nvram set ath1_net_mode=disabled")
      self.ssh.exec_command("nvram set ath1_gmode=-1")

  @Setup(restart=True)
  def SetWifi(self, active):
    """Turns both the 2.4GHz and 5GHz radios on or off."""
    self.Set2ghz.nosetup(self, active)
    self.Set5ghz.nosetup(self, active)

  @Setup(restart=True)
  def Set2ghzSSID(self, ssid):
    """Sets the SSID for the 2.4GHz radio."""
    ssid = self.SanitizeSSID(ssid)
    logger.info("Setting 2GHz SSID to %s for %s.", ssid, self.hostname)
    self.ssh.exec_command("nvram set ath0_ssid=%s" % ssid)

  @Setup(restart=True)
  def Set5ghzSSID(self, ssid):
    """Sets the SSId for the 5GHz radio."""
    ssid = self.SanitizeSSID(ssid)
    logger.info("Setting 5GHz SSID to %s for %s.", ssid, self.hostname)
    self.ssh.exec_command("nvram set ath1_ssid=%s" % ssid)

  @Setup(restart=True)
  def SetSSID(self, ssid):
    """Sets the SSID for both the 2.4GHz and 5GHz radios."""
    self.Set2ghzSSID.nosetup(self, ssid)
    self.Set5ghzSSID.nosetup(self, ssid)

  @Setup(restart=True)
  def Set2ghzChannel(self, channel):
    """Sets the channel that the 2.4GHz radio broadcasts on."""
    channel = str(channel)
    if channel in GBAND:
      logger.info("Setting radio on %s to broadcast on channel %s.",
                  self.hostname, channel)
      self.ssh.exec_command("nvram set ath0_channel=%s" % GBAND[channel])
    else:
      print "Invalid channel number"

  @Setup(restart=True)
  def Set5ghzChannel(self, channel):
    """Sets the channel that the 5GHz radio broadcasts on."""
    channel = str(channel)
    if channel in ABAND:
      logger.info("Setting radio on %s to broadcast on channel %s.",
                  self.hostname, channel)
      self.ssh.exec_command("nvram set ath1_channel=%s" % ABAND[channel])
    else:
      print "Invalid channel number"

  # TODO: Determine how DD-WRT escapes special characters and reproduce
  # that here. Technically, "; erase nvram" or "; nvram set password=; reboot"
  # are valid SSIDs
  @staticmethod
  def SanitizeSSID(ssid):
    """Ensure that the SSID name isn't vulnerable to code injection.

    Without sanitization, something like "; erase nvram" could be passed and
    cause all sorts of problems. This method ensures that the ssid contains
    only certain punctuation and has a max length of 32 characters.

    Args:
      ssid: The unsanitized input.
    Returns:
      The sanitized output.
    Raises:
      SSIDError: The given SSID is invalid
    """
    if re.search(r"^\"[\w\d\s-]{0,30}\"$", ssid):
      return ssid
    elif re.search(r"^[\w\d\s-]{0,32}$", ssid):
      return "\"%s\"" % ssid
    else:
      raise SSIDError("Invalid SSID")
