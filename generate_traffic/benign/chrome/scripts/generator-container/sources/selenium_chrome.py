import argparse, sys, time, logging

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException
#from selenium.webdriver.chrome.options import Options as ChromeOptions

from xvfbwrapper import Xvfb


logger = logging.getLogger("chrome-traffic-capture")
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


def get_chrome_webdriver(uri, use_get, doh=True, no_telemetry=False, append_log=False):
    options = webdriver.ChromeOptions()

    # https://chromium.googlesource.com/chromium/src/+/master/chrome/common/chrome_switches.cc
    # https://source.chromium.org/chromium/chromium/src/+/main:chrome/test/chromedriver/chrome_launcher.cc?q=f:chrome_launcher%20%20kDesktopSwitches&ss=chromium # default switches with ChromeDriver
    #options.add_argument("--headless=new")
    #options.add_argument("--start-maximized")
    #options.add_argument("--incognito")
    #options.add_argument("--bwsi")

    local_state = dict()

    if no_telemetry:
        # https://github.com/GoogleChrome/chrome-launcher/blob/main/docs/chrome-flags-for-tools.md#commonly-unwanted-browser-features
        # options.add_argument("--disable-client-side-phishing-detection")
        # options.add_argument("--disable-component-extensions-with-background-pages")
        # options.add_argument("--disable-default-apps")
        # options.add_argument("--disable-extensions")
        # options.add_argument("--disable-features=InterestFeedContentSuggestions")
        # options.add_argument("--disable-features=Translate")
        # options.add_argument("--no-default-browser-check")
        # options.add_argument("--disable-default-browser-promo")
        # options.add_argument("--no-first-run")
        # options.add_argument("--ash-no-nudges")
        # options.add_argument("--disable-search-engine-choice-screen")
        # options.add_argument("--propagate-iph-for-testing")

        # options.add_argument("--disable-background-networking")
        # options.add_argument("--disable-component-update")
        # options.add_argument("--disable-domain-reliability")
        # options.add_argument("--disable-features=AutofillServerCommunication")
        # options.add_argument("--disable-features=CertificateTransparencyComponentUpdater")
        # options.add_argument("--disable-sync")
        options.add_argument("--disable-features=OptimizationHints")
        # options.add_argument("--disable-features=MediaRouter")

        # local_state["signin.allowed"] = False
        # local_state["signin.allowed_on_next_startup"] = False
        # local_state["start_sync_settings_on_session_start"] = False
        # options.add_argument("--skip-force-online-signin-for-testing")
        # options.add_argument("--disable-features=ImprovedCookieControls")
        # options.add_argument("--disable-features=PrivacySandboxSettings4")

        # disable "google accounts and id administration" https://accounts.google.com/ListAccounts?gpsia=1&source=ChromiumBrowser&json=standard
        # https://github.com/brave/brave-browser/issues/1312
        # https://source.chromium.org/chromium/chromium/src/+/main:google_apis/gaia/gaia_switches.h
        # https://source.chromium.org/chromium/chromium/src/+/main:google_apis/gaia/gaia_switches.cc
        # https://source.chromium.org/chromium/chromium/src/+/main:google_apis/gaia/gaia_urls.cc

        # options.add_argument("--disable-gaia-services")
        options.add_argument("--gaia-url=http://0.0.0.0")
        # options.add_argument("--google-url=localhost")
        # options.add_argument("--google-apis-url=localhost")
        # options.add_argument("--oauth-account-manager-url=localhost")
        #options.add_argument("--no-pings")

        # disable captive portal check www.gstatic.com (hard-coded in source)
        # https://source.chromium.org/chromium/chromium/src/+/main:components/captive_portal/core/captive_portal_detector.cc
        # https://support.google.com/chrome/a/thread/301331434/captive-portal-redirection-issue-with-chrome-browser
        # https://github.com/uazo/cromite/blob/master/build/patches/Remove-detection-of-captive-portals.patch
        # https://github.com/win32ss/supermium/issues/1044
        # https://superuser.com/questions/1636190/the-url-http-www-gstatic-com-generate-204-is-opening-up-for-no-reason-in-chr
        # https://github.com/brave/brave-browser/issues/1715
        # https://support.google.com/chrome/a/thread/301331434/captive-portal-redirection-issue-with-chrome-browser
        # https://docs.google.com/document/d/1k-gP2sswzYNvryu9NcgN7q5XrsMlUdlUdoW9WRaEmfM/edit?tab=t.0

        options.add_argument("--host-resolver-rules=MAP www.gstatic.com 0.0.0.0") # doesn't work
        options.add_argument("--host-rules=MAP www.gstatic.com 0.0.0.0") # doesn't work
        #options.add_argument("--connectivity-check-url=http://0.0.0.0") # https://clients3.google.com/generate_204
        local_state["alternate_error_pages.enabled"] = False # doesn't work

    # # disable cache
    # options.add_argument("--disk-cache-size=0")

    # https://www.chromium.org/chromium-os/developer-library/guides/preferences/policy-prefs/
    # https://stackoverflow.com/questions/70268357/how-to-enable-doh-settings-in-chrome-driver-in-selenium
    # https://stackoverflow.com/questions/69659111/how-to-disable-dns-over-https-in-selenium
    # https://stackoverflow.com/questions/58611579/how-to-set-preferences-for-chrome-in-selenium-python

    local_state["net.quic_allowed"] = False # disable HTTP/3, not working
    #local_state["ssl.ech_enabled"] = False # disable ECH
    #local_state["dns_over_https.mode"] = "secure" if doh else "off" # forced DoH
    #local_state["dns_over_https.templates"] = uri if not use_get else uri + "{?dns}" # set DoH request method
    if doh:
        local_state["dns_over_https.mode"] = "secure" # forced DoH
        if not use_get:
            local_state["dns_over_https.templates"] = uri # DoH default POST method URI
        else:
            local_state["dns_over_https.templates"] = uri + "{?dns}" # use DoH GET method
    else:
        local_state["dns_over_https.mode"] = "off"

    options.add_experimental_option('localState', local_state)
    options.add_argument('--disable-quic') # disable HTTP/3, working

    #options.add_argument('--ignore-ssl-errors=yes')
    #options.add_argument('--ignore-certificate-errors')
    #options.add_argument('--ssl-version-min=tls1.0') # supported values are "tls1.2", "tls1.3"
    #options.accept_insecure_certs = True

    options.unhandled_prompt_behavior = "accept"

    options.binary_location = "/usr/bin/google-chrome"

    #options.add_argument("--enable-logging")
    #options.add_argument("--log-file=/capture/chrome.log")
    #options.add_argument("--v=1")

    if append_log:
        service = webdriver.ChromeService(executable_path="/usr/bin/chromedriver", service_args=['--append-log', '--readable-timestamp'], log_output="/capture/chromedriver.log")
    else:
        service = webdriver.ChromeService(executable_path="/usr/bin/chromedriver", service_args=['--readable-timestamp'], log_output="/capture/chromedriver.log")

    return webdriver.Chrome(options=options, service=service)


def run_single_query(domain, uri=None, use_get=False, doh=True, no_telemetry=False, append_log=False, vnc=False):
    logger.info("Running single query")
    
    if not vnc:
        virtual_display = Xvfb(width=1366, height=768)
        virtual_display.start()

    driver = get_chrome_webdriver(uri, use_get, doh, no_telemetry=False, append_log=False)
    driver.set_page_load_timeout(15)
    driver.maximize_window()

    try:
        logger.debug("Starting driver.get: " + domain)
        driver.get("https://" + domain)
        #print(driver.title)
        logger.debug("Successful get")
        # logger.debug("Taking screenshot")
        # time.sleep(2)
        # driver.save_screenshot("/capture/page_screenshot.png") # same as chrome
    except TimeoutException as e:
        logger.warning("ExceptionOccured: TimeoutException")
    except Exception as e:
        logger.warning("ExceptionOccured: " + str(e))

    try:
        # https://developer.mozilla.org/en-US/docs/Web/Performance/Navigation_and_resource_timings
        # https://stackoverflow.com/questions/53603906/chrome-performance-timing-wrong-outputs-not-matching-with-dev-tools
        # https://stackoverflow.com/questions/65758237/difference-when-comparing-the-timing-results-of-performance-api-and-chromes-dev
        logger.debug("Getting timings")
        timing = driver.execute_script("return performance.getEntriesByType('navigation')[0]") # milliseconds
        print(str(round(timing["startTime"])) + ","
            + str(round(timing["domainLookupStart"])) + ","
            + str(round(timing["domainLookupEnd"])) + ","
            + str(round(timing["connectStart"])) + ","
            + str(round(timing["connectEnd"])) + ","
            + str(round(timing["requestStart"])) + ","
            + str(round(timing["responseStart"])) + ","
            + str(round(timing["responseEnd"])) + ","
            + str(round(timing["domComplete"])))
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
    parser.add_argument("--vnc", action="store_true", help="view through http://localhost:7902/?autoconnect=1&resize=scale&password=secret")

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
