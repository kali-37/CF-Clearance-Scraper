from __future__ import annotations

import asyncio
from datetime import datetime
import random
from enum import Enum
from typing import Any, Dict, Final, Iterable, List, Optional

import latest_user_agents
import user_agents
import zendriver
from selenium_authenticated_proxy import SeleniumAuthenticatedProxy
from zendriver import cdp
from zendriver.cdp.emulation import UserAgentBrandVersion, UserAgentMetadata
from zendriver.cdp.network import Cookie
from zendriver.core.element import Element

import logging

def get_logger(name, level="INFO", async_mode=True):
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger

logger = get_logger(__name__, level="INFO", async_mode=True)





# Type alias for JSON dictionary
T_JSON_DICT = Dict[str, Any]

COMMAND: Final[str] = (
    '{name}: {binary} --header "Cookie: {cookies}" --header "User-Agent: {user_agent}" {url}'
)


def get_chrome_user_agent() -> str:
    """
    Get a random up-to-date Chrome user agent string.

    Returns
    -------
    str
        The user agent string.
    """
    chrome_user_agents = [
        user_agent
        for user_agent in latest_user_agents.get_latest_user_agents()
        if "Chrome" in user_agent and "Edg" not in user_agent
    ]
    return random.choice(chrome_user_agents)


class ChallengePlatform(Enum):
    """Cloudflare challenge platform types."""

    JAVASCRIPT = "non-interactive"
    MANAGED = "managed"
    INTERACTIVE = "interactive"


class CloudflareSolver:
    """
    A class for solving Cloudflare challenges with Zendriver.

    Parameters
    ----------
    user_agent : Optional[str]
        The user agent string to use for the browser requests.
    timeout : float
        The timeout in seconds to use for browser actions and solving challenges.
    http2 : bool
        Enable or disable the usage of HTTP/2 for the browser requests.
    http3 : bool
        Enable or disable the usage of HTTP/3 for the browser requests.
    headless : bool
        Enable or disable headless mode for the browser (not supported on Windows).
    proxy : Optional[str]
        The proxy server URL to use for the browser requests.
    """

    def __init__(
        self,
        *,
        user_agent: Optional[str],
        timeout: float,
        http2: bool,
        http3: bool,
        headless: bool,
        proxy: Optional[str],
    ) -> None:
        config = zendriver.Config(headless=headless)

        if user_agent is not None:
            config.add_argument(f"--user-agent={user_agent}")

        auth_proxy = SeleniumAuthenticatedProxy(proxy)
        auth_proxy.enrich_chrome_options(config)

        self.driver = zendriver.Browser(config)
        self._timeout = timeout

    async def __aenter__(self) -> CloudflareSolver:
        await self.driver.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.driver.stop()

    @staticmethod
    def _format_cookies(cookies: Iterable[Any]) -> List[T_JSON_DICT]:
        """
        Format cookies into a list of JSON cookies.

        Parameters
        ----------
        cookies : Iterable[Any]
            List of cookies.

        Returns
        -------
        List[T_JSON_DICT]
            List of JSON cookies.
        """
        formatted_cookies = []
        for cookie in cookies:
            if hasattr(cookie, "to_json"):
                formatted_cookies.append(cookie.to_json())
            else:
                formatted_cookies.append(cookie)
        return formatted_cookies

    @staticmethod
    def extract_clearance_cookie(
        cookies: Iterable[T_JSON_DICT],
    ) -> Optional[T_JSON_DICT]:
        """
        Extract the Cloudflare clearance cookie from a list of cookies.

        Parameters
        ----------
        cookies : Iterable[T_JSON_DICT]
            List of cookies.

        Returns
        -------
        Optional[T_JSON_DICT]
            The Cloudflare clearance cookie. Returns None if the cookie is not found.
        """

        for cookie in cookies:
            if cookie["name"] == "cf_clearance":
                return cookie

        return None

    async def get_user_agent(self) -> str:
        """
        Get the current user agent string.

        Returns
        -------
        str
            The user agent string.
        """
        result = await self.driver.main_tab.evaluate("navigator.userAgent")
        if isinstance(result, str):
            return result
        elif isinstance(result, tuple) and len(result) > 0:
            return str(result[0])
        else:
            return str(result)

    async def get_cookies(self) -> List[T_JSON_DICT]:
        """
        Get all cookies from the current page.

        Returns
        -------
        List[T_JSON_DICT]
            List of cookies.
        """
        return self._format_cookies(await self.driver.cookies.get_all())

    async def set_user_agent_metadata(self, user_agent: str) -> None:
        """
        Set the user agent metadata for the browser.

        Parameters
        ----------
        user_agent : str
            The user agent string to parse information from.
        """
        device = user_agents.parse(user_agent)

        self.driver.main_tab.feed_cdp(
            cdp.network.set_user_agent_override(
                user_agent=user_agent,
                platform=device.os.family,
                user_agent_metadata=UserAgentMetadata(
                    platform=device.os.family,
                    platform_version=device.os.version_string,
                    architecture="x86_64",
                    model=device.device.model or "",
                    mobile=device.is_mobile,
                    brands=[
                        UserAgentBrandVersion(
                            brand="Google Chrome",
                            version=str(device.browser.version[0]),
                        ),
                        UserAgentBrandVersion(brand="Not-A.Brand", version="8"),
                        UserAgentBrandVersion(
                            brand="Chromium", version=str(device.browser.version[0])
                        ),
                    ],
                ),
            )
        )

    async def detect_challenge(self) -> Optional[ChallengePlatform]:
        """
        Detect the Cloudflare challenge platform on the current page.

        Returns
        -------
        Optional[ChallengePlatform]
            The Cloudflare challenge platform.
        """
        html = await self.driver.main_tab.get_content()

        for platform in ChallengePlatform:
            if f"cType: '{platform.value}'" in html:
                return platform

        return None

    async def solve_challenge(self) -> None:
        """Solve the Cloudflare challenge on the current page."""
        start_timestamp = datetime.now()

        while (
            self.extract_clearance_cookie(await self.get_cookies()) is None
            and await self.detect_challenge() is not None
            and (datetime.now() - start_timestamp).seconds < self._timeout
        ):
            widget_input = await self.driver.main_tab.find("input")

            if widget_input.parent is None or not widget_input.parent.shadow_roots:
                await asyncio.sleep(0.25)
                continue

            challenge = Element(
                widget_input.parent.shadow_roots[0],
                self.driver.main_tab,
                widget_input.parent.tree,
            )

            challenge = challenge.children[0]

            if (
                isinstance(challenge, Element)
                and "display: none;" not in challenge.attrs["style"]
            ):
                await asyncio.sleep(1)

                try:
                    await challenge.get_position()
                except Exception:
                    continue

                await challenge.mouse_click()


async def main_duo(
    url: str,
    proxy: str = "",
    logger=logger,
    headed=False,
    user_agent=None,
    timeout=30.0,
):
    logger = logger
    logger.info("Launching %s browser...", "headed" if headed else "headless")

    challenge_messages = {
        ChallengePlatform.JAVASCRIPT: "Solving Cloudflare challenge [JavaScript]...",
        ChallengePlatform.MANAGED: "Solving Cloudflare challenge [Managed]...",
        ChallengePlatform.INTERACTIVE: "Solving Cloudflare challenge [Interactive]...",
    }

    user_agent = get_chrome_user_agent() if user_agent is None else user_agent

    async with CloudflareSolver(
        user_agent=user_agent,
        timeout=timeout,
        http2=False,
        http3=False,
        headless=not headed,
        proxy=proxy,
    ) as solver:
        logger.info("Going to %s...", url)

        try:
            await solver.driver.get(url)
        except asyncio.TimeoutError as err:
            logger.error(err)
            return

        all_cookies = await solver.get_cookies()
        clearance_cookie = solver.extract_clearance_cookie(all_cookies)

        if clearance_cookie is None:
            await solver.set_user_agent_metadata(await solver.get_user_agent())
            challenge_platform = await solver.detect_challenge()

            if challenge_platform is None:
                logger.error("No Cloudflare challenge detected.")
                return

            logger.info(challenge_messages[challenge_platform])

            try:
                await solver.solve_challenge()
            except asyncio.TimeoutError:
                pass

            all_cookies = await solver.get_cookies()
            clearance_cookie = solver.extract_clearance_cookie(all_cookies)

        user_agent = await solver.get_user_agent()

    if clearance_cookie is None:
        logger.error("Failed to retrieve a Cloudflare clearance cookie.")
        return

    return {
        "cf_clearance": clearance_cookie["value"],
        "user_agent": user_agent,
    }

if __name__ == "__main__":
    # TESTING DEBUG
    import argparse

    parser = argparse.ArgumentParser(description="Cloudflare Clearance Scraper")
    parser.add_argument("url", type=str, help="The URL to scrape")
    parser.add_argument("--proxy", type=str, default="", help="Proxy server URL")
    parser.add_argument("--headed", action="store_true", help="Run browser in headed mode")
    parser.add_argument(
        "--user-agent", type=str, default=None, help="Custom user agent string"
    )
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="Timeout for solving challenges"
    )

    args = parser.parse_args()

    logger.info(asyncio.run(
        main_duo(
            url=args.url,
            proxy=args.proxy,
            headed=args.headed,
            user_agent=args.user_agent,
            timeout=args.timeout,
        )
    ))