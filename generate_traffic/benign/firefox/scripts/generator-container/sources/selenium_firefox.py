import argparse, sys, os, time, logging

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException
#from selenium.webdriver.firefox.options import Options as FirefoxOptions

from xvfbwrapper import Xvfb


logger = logging.getLogger("firefox-traffic-capture")
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


def get_firefox_webdriver(uri, use_get, doh=True, no_telemetry=False, append_log=False):
    options = webdriver.FirefoxOptions()

    # https://firefox-source-docs.mozilla.org/testing/geckodriver/Profiles.html # default switches with geckodriver
    #options.add_argument("--headless")
    #options.add_argument("--private")

    if no_telemetry:
        # firefox.settings.services.mozilla.com
        # content-signature-2.cdn.mozilla.net
        # firefox-settings-attachments.cdn.mozilla.net
        # https://github.com/mozilla-services/autograph/tree/main/signer/contentsignature
        # https://wiki.archlinux.org/title/Firefox/Privacy#Editing_the_contents_of_omni.ja
        # https://gitlab.torproject.org/tpo/applications/tor-browser/-/issues/40788
        #options.set_preference("services.settings.server", "")
        options.set_preference('network.trr.exclude-etc-hosts', True) # exclude URL in /etc/hosts file
        #options.set_preference('network.trr.excluded-domains', "firefox.settings.services.mozilla.com,content-signature-2.cdn.mozilla.net,firefox-settings-attachments.cdn.mozilla.net") # comma separated list of domains to use DNS instead
        
        
        # https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections
        # https://wiki.mozilla.org/Security/Safe_Browsing

        # firefox-settings-attachments.cdn.mozilla.net
        # options.set_preference("browser.search.update", False)

        # # firefox.settings.services.mozilla.com
        # options.set_preference("signon.management.page.breach-alerts.enabled", False)
        # options.set_preference("signon.management.page.vulnerable-passwords.enabled", False)
        # options.set_preference("signon.management.page.breachAlertUrl", "")

        # options.set_preference("extensions.blocklist.enabled", False)

        # options.set_preference("privacy.trackingprotection.enabled", False)
        # options.set_preference("privacy.trackingprotection.annotate_channels", False)
        # options.set_preference("privacy.trackingprotection.fingerprinting.enabled", False)
        # options.set_preference("privacy.trackingprotection.cryptomining.enabled", False)
        # options.set_preference("privacy.trackingprotection.socialtracking.enabled", False)
        # options.set_preference("privacy.trackingprotection.block_cookies.enabled", False)
        # options.set_preference("privacy.trackingprotection.emailtracking.enabled", False)
        # options.set_preference("privacy.trackingprotection.emailtracking.data_collection.enabled", False)
        # options.set_preference("privacy.trackingprotection.socialtracking.enabled", False)
        # options.set_preference("privacy.trackingprotection.socialtracking.enabled", False)

        # options.set_preference("browser.contentblocking.enabled", False)
        # options.set_preference("browser.contentblocking.database.enabled", False)
        # options.set_preference("browser.safebrowsing.downloads.enabled", False)
        # options.set_preference("browser.safebrowsing.downloads.remote.enabled", False)
        # options.set_preference("browser.safebrowsing.blockedURIs.enabled", False)
        # options.set_preference("browser.safebrowsing.malware.enabled", False)
        # options.set_preference("browser.safebrowsing.phishing.enabled", False)
        # options.set_preference("browser.safebrowsing.downloads.enabled", False)
        # options.set_preference("browser.safebrowsing.downloads.remote.enabled", False)

        # options.set_preference("browser.newtabpage.enabled", False)
        # options.set_preference("browser.newtabpage.enhanced", False)
        # options.set_preference("browser.newtabpage.introShown", False)
        # options.set_preference("browser.newtabpage.directory.ping", "")
        # options.set_preference("browser.newtabpage.directory.source", "data:application/json,{}")
        # options.set_preference("browser.newtab.preload", False)
        # options.set_preference("toolkit.telemetry.reportingpolicy.firstRun", False)

        options.set_preference("network.captive-portal-service.enabled", False) # disable detectportal.firefox.com
        # options.set_preference("network.connectivity-service.enabled", False) # disable multiple checks

    # # cache
    # options.set_preference('browser.cache.disk.enable', False)
    # options.set_preference('browser.cache.memory.enable', False)
    # options.set_preference('browser.cache.offline.enable', False)
    # options.set_preference('network.http.use-cache', False)
    # options.set_preference("network.dnsCacheEntries", 0)
    # options.set_preference("network.dnsCacheExpiration", 0)

    # options.set_preference("http.response.timeout", 10)
    # options.set_preference("dom.max_script_run_time", 10)

    # options.set_preference("security.OCSP.enabled", 0) # disable OCSP

    options.set_preference("network.http.http3.enable", False) # disable HTTP/3
    #options.set_preference("network.dns.echconfig.enabled", False) # disable ECH
    #options.set_preference("network.dns.disableIPv6", True) # disable AAAA lookup
    
    # https://wiki.mozilla.org/Trusted_Recursive_Resolver
    if doh:
        options.set_preference('network.trr.mode', 3) # forced DoH
        options.set_preference("network.trr.uri", uri) # DoH default POST
        if use_get:
            options.set_preference("network.trr.useGET", True) # use DoH GET method
    else:
        options.set_preference('network.trr.mode', 5) # off by choice

    #options.set_preference("network.trr.send_user-agent_headers", False)

    #options.accept_insecure_certs = True

    options.unhandled_prompt_behavior = "accept"

    options.binary_location = "/usr/bin/firefox"

    # firefox WebDriverException: Message: Unable to obtain working Selenium Manager binary
    # https://stackoverflow.com/questions/71630291/selenium-common-exceptions-webdriverexception-message-process-unexpectedly-clo
    # https://stackoverflow.com/questions/46809135/webdriver-exceptionprocess-unexpectedly-closed-with-status-1
    # https://firefox-source-docs.mozilla.org/testing/geckodriver/Flags.html
    #service = webdriver.FirefoxService(executable_path="/usr/bin/geckodriver", service_args=['--log', 'config', '--log-no-truncate'], log_output="/capture/geckodriver.log")
    service = webdriver.FirefoxService(executable_path="/usr/bin/geckodriver", service_args=['--log', 'config'], log_output="/capture/geckodriver.log")
    #service = webdriver.FirefoxService(executable_path="/usr/bin/geckodriver")

    return webdriver.Firefox(options=options, service=service)


def run_single_query(domain, uri=None, use_get=False, doh=True, no_telemetry=False, append_log=False, vnc=False):
    logger.info("Running single query")

    if not vnc:
        virtual_display = Xvfb(width=1366, height=768)
        virtual_display.start()

    if append_log:
        if os.path.exists("/capture/geckodriver.log"):
            with open("/capture/geckodriver.log", "a") as file:
                file.write("\n\n\n")
    else:
        if os.path.exists("/capture/geckodriver.log"):
            os.remove("/capture/geckodriver.log")
    
    driver = get_firefox_webdriver(uri, use_get, doh, no_telemetry, append_log)
    driver.set_page_load_timeout(15)
    driver.maximize_window()

    try:
        logger.debug("Starting driver.get: " + domain)
        driver.get("https://" + domain)
        #print(driver.title)
        logger.debug("Successful get")
        # logger.debug("Taking screenshot")
        # time.sleep(2)
        # #driver.save_full_page_screenshot("/capture/full_page_screenshot.png")
        # driver.save_screenshot("/capture/page_screenshot.png") # same as chrome
    except TimeoutException as e:
        logger.warning("ExceptionOccured: TimeoutException")
    except Exception as e:
        logger.warning("ExceptionOccured: " + str(e))
    
    try:
        # https://developer.mozilla.org/en-US/docs/Web/Performance/Navigation_and_resource_timings
        logger.debug("Getting timings")
        timing = driver.execute_script("return performance.getEntriesByType('navigation')[0]") # milliseconds
        print(str(timing["startTime"]) + ","
            + str(timing["domainLookupStart"]) + ","
            + str(timing["domainLookupEnd"]) + ","
            + str(timing["connectStart"]) + ","
            + str(timing["connectEnd"]) + ","
            + str(timing["requestStart"]) + ","
            + str(timing["responseStart"]) + ","
            + str(timing["responseEnd"]) + ","
            + str(timing["domComplete"]))
    except UnexpectedAlertPresentException as e:
        logger.warning("ExceptionOccured: UnexpectedAlertPresentException")
        logger.warning("Accepting alert")
        alert = driver.switch_to().alert
        alert.accept()
    except NoAlertPresentException as e:
        logger.warning("ExceptionOccured: NoAlertPresentException")
    except Exception as e:
        logger.warning("ExceptionOccured: " + str(e))

    #driver.delete_all_cookies()

    driver.quit()
    
    if not vnc:
        virtual_display.stop()

    logger.info("Finished single query")
    print()


# https://mitmproxy.org/


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", nargs="?", type=str, default="example.org", help="domain to query")
    parser.add_argument("--resolver", nargs="?", type=str, const="https://cloudflare-dns.com/dns-query", default="https://cloudflare-dns.com/dns-query", help="resolver URI (default: https://cloudflare-dns.com/dns-query)")
    parser.add_argument("--doh_method", nargs="?", type=str, const="DOH_POST", default="DOH_POST", help="DOH_POST | DOH_GET | DISABLED (default: DOH_POST)")
    parser.add_argument("--no_telemetry", action="store_true", help="disable all browsers telemetry")
    parser.add_argument("--vnc", action="store_true", help="view through http://localhost:7901/?autoconnect=1&resize=scale&password=secret")

    args = parser.parse_args()

    #domain = "https://quic.nginx.org/"
    #domain = "https://cloudflare-quic.com/"
    #domain = "https://one.one.one.one/help/"
    #domain = "https://on.quad9.net/"
    #domain = "https://umbrella.cisco.com/doh-help"

    if args.doh_method == "DOH_POST":
        run_single_query(args.domain, uri=args.resolver, use_get=False, no_telemetry=args.no_telemetry, vnc=args.vnc)
    elif args.doh_method == "DOH_GET":
        run_single_query(args.domain, uri=args.resolver, use_get=True, no_telemetry=args.no_telemetry, vnc=args.vnc)
    elif args.doh_method == "DISABLED":
        run_single_query(args.domain, doh=False, no_telemetry=args.no_telemetry, vnc=args.vnc)
