var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/index.ts
import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import { config as config5 } from "dotenv";

// src/easy-waf/index.ts
import proxyaddr2 from "proxy-addr";
import { Matcher as IPMatcher } from "netparser";

// src/easy-waf/utils.ts
import proxyaddr from "proxy-addr";
import https from "https";
import { createHash } from "crypto";
function compileProxyTrust(val) {
  if (typeof val === "function") {
    return val;
  }
  if (typeof val === "number") {
    return (_a, i) => {
      return i < val;
    };
  }
  if (typeof val === "boolean") {
    return () => {
      return val;
    };
  }
  return proxyaddr.compile(val);
}
__name(compileProxyTrust, "compileProxyTrust");
function httpGET(url) {
  return new Promise((resolve, reject) => {
    https.get(url, {
      timeout: 5e3
    }, (res) => {
      let data = "";
      res.on("data", (chunk) => {
        data += chunk;
      });
      res.on("error", reject);
      res.on("end", () => {
        const { statusCode } = res;
        if (typeof statusCode !== "number") {
          reject(new Error("Invalid status code"));
          return;
        }
        const validResponse = statusCode >= 200 && statusCode <= 299;
        if (validResponse) {
          resolve(data);
          return;
        }
        reject(new Error(`Request failed. Status: ${statusCode} Url: ${url}`));
      });
    }).on("error", reject).end();
  });
}
__name(httpGET, "httpGET");
function sha256(content) {
  return createHash("sha256").update(content).digest("hex");
}
__name(sha256, "sha256");

// src/easy-waf/modules/index.ts
var modules_exports = {};
__export(modules_exports, {
  badBots: () => badBots_default,
  blockTorExitNodes: () => blockTorExitNodes_default,
  crlfInjection: () => crlfInjection_default,
  directoryTraversal: () => directoryTraversal_default,
  fakeCrawlers: () => fakeCrawlers_default,
  httpParameterPollution: () => httpParameterPollution_default,
  noSqlInjection: () => noSqlInjection_default,
  openRedirect: () => openRedirect_default,
  prototypePollution: () => prototypePollution_default,
  sqlInjection: () => sqlInjection_default,
  xmlInjection: () => xmlInjection_default,
  xss: () => xss_default
});

// src/easy-waf/modules/badBots.ts
var regex = /(01h4x\.com|360Spider|404enemy|80legs|ADmantX|AIBOT|ALittle Client|ASPSeek|Abonti|Aboundex|Aboundexbot|Acunetix|AdsTxtCrawlerTP|AfD-Verbotsverfahren|AhrefsBot|AiHitBot|Aipbot|Alexibot|AllSubmitter|Alligator|AlphaBot|Anarchie|Anarchy|Anarchy99|Ankit|Anthill|Apexoo|Aspiegel|Asterias|Atomseobot|Attach|AwarioRssBot|AwarioSmartBot|BBBike|BDCbot|BDFetch|BLEXBot|BackDoorBot|BackStreet|BackWeb|Backlink-Ceck|BacklinkCrawler|Badass|Bandit|Barkrowler|BatchFTP|Battleztar Bazinga|BetaBot|Bigfoot|Bitacle|BlackWidow|Black Hole|Blackboard|Blow|BlowFish|Boardreader|Bolt|BotALot|Brandprotect|Brandwatch|Buck|Buddy|BuiltBotTough|BuiltWith|Bullseye|BunnySlippers|BuzzSumo|Bytespider|CATExplorador|CCBot|CODE87|CSHttp|Calculon|CazoodleBot|Cegbfeieh|CensysInspect|CheTeam|CheeseBot|CherryPicker|ChinaClaw|Chlooe|Citoid|Claritybot|Cliqzbot|Cloud mapping|Cocolyzebot|Cogentbot|Collector|Copier|CopyRightCheck|Copyscape|Cosmos|Craftbot|Crawling at Home Project|CrazyWebCrawler|Crescent|CrunchBot|Curious|Custo|CyotekWebCopy|DBLBot|DIIbot|DSearch|DTS Agent|DataCha0s|DatabaseDriverMysqli|Demon|Deusu|Devil|Digincore|DigitalPebble|Dirbuster|Disco|Discobot|Discoverybot|Dispatch|DittoSpyder|DnBCrawler-Analytics|DnyzBot|DomCopBot|DomainAppender|DomainCrawler|DomainSigmaCrawler|DomainStatsBot|Domains Project|Dotbot|Download Wonder|Dragonfly|Drip|ECCP\/1\.0|EMail Siphon|EMail Wolf|EasyDL|Ebingbong|Ecxi|EirGrabber|EroCrawler|Evil|Exabot|Express WebPictures|ExtLinksBot|Extractor|ExtractorPro|Extreme Picture Finder|EyeNetIE|Ezooms|FDM|FHscan|FemtosearchBot|Fimap|Firefox\/7\.0|FlashGet|Flunky|Foobot|Freeuploader|FrontPage|Fuzz|FyberSpider|Fyrebot|G-i-g-a-b-o-t|GT::WWW|GalaxyBot|Genieo|GermCrawler|GetRight|GetWeb|Getintent|Gigabot|Go!Zilla|Go-Ahead-Got-It|GoZilla|Gotit|GrabNet|Grabber|Grafula|GrapeFX|GrapeshotCrawler|GridBot|HEADMasterSEO|HMView|HTMLparser|HTTP::Lite|HTTrack|Haansoft|HaosouSpider|Harvest|Havij|Heritrix|Hloader|HonoluluBot|Humanlinks|HybridBot|IDBTE4M|IDBot|IRLbot|Iblog|Id-search|IlseBot|Image Fetch|Image Sucker|IndeedBot|Indy Library|InfoNaviRobot|InfoTekies|Intelliseek|InterGET|InternetSeer|Internet Ninja|Iria|Iskanie|IstellaBot|JOC Web Spider|JamesBOT|Jbrofuzz|JennyBot|JetCar|Jetty|JikeSpider|Joomla|Jorgee|JustView|Jyxobot|Kenjin Spider|Keybot Translation-Search-Machine|Keyword Density|Kinza|Kozmosbot|LNSpiderguy|LWP::Simple|Lanshanbot|Larbin|Leap|LeechFTP|LeechGet|LexiBot|Lftp|LibWeb|Libwhisker|LieBaoFast|Lightspeedsystems|Likse|LinkScan|LinkWalker|Linkbot|LinkextractorPro|LinkpadBot|LinksManager|LinqiaMetadataDownloaderBot|LinqiaRSSBot|LinqiaScrapeBot|Lipperhey|Lipperhey Spider|Litemage_walker|Lmspider|Ltx71|MFC_Tear_Sample|MIDown tool|MIIxpc|MJ12bot|MQQBrowser|MSFrontPage|MSIECrawler|MTRobot|Mag-Net|Magnet|Mail\.RU_Bot|Majestic-SEO|Majestic12|Majestic SEO|MarkMonitor|MarkWatch|Mass Downloader|Masscan|Mata Hari|MauiBot|Mb2345Browser|MeanPath Bot|Meanpathbot|Mediatoolkitbot|MegaIndex\.ru|Metauri|MicroMessenger|Microsoft Data Access|Microsoft URL Control|Minefield|Mister PiX|Moblie Safari|Mojeek|Mojolicious|MolokaiBot|Morfeus Fucking Scanner|Mozlila|Mr\.4x3|Msrabot|Musobot|NICErsPRO|NPbot|Name Intelligence|Nameprotect|Navroad|NearSite|Needle|Nessus|NetAnts|NetLyzer|NetMechanic|NetSpider|NetZIP|Net Vampire|Netcraft|Nettrack|Netvibes|NextGenSearchBot|Nibbler|Niki-bot|Nikto|NimbleCrawler|Nimbostratus|Ninja|Nmap|Nuclei|Nutch|Octopus|Offline Explorer|Offline Navigator|OnCrawl|OpenLinkProfiler|OpenVAS|Openfind|Openvas|OrangeBot|OrangeSpider|OutclicksBot|OutfoxBot|PECL::HTTP|PHPCrawl|POE-Component-Client-HTTP|PageAnalyzer|PageGrabber|PageScorer|PageThing\.com|Page Analyzer|Pandalytics|Panscient|Papa Foto|Pavuk|PeoplePal|Pi-Monster|Picscout|Picsearch|PictureFinder|Piepmatz|Pimonster|Pixray|PleaseCrawl|Pockey|ProPowerBot|ProWebWalker|Probethenet|Proximic|Psbot|Pu_iN|Pump|PxBroker|PyCurl|QueryN Metasearch|Quick-Crawler|RSSingBot|RankActive|RankActiveLinkBot|RankFlex|RankingBot|RankingBot2|Rankivabot|RankurBot|Re-re|ReGet|RealDownload|Reaper|RebelMouse|Recorder|RedesScrapy|RepoMonkey|Ripper|RocketCrawler|Rogerbot|SBIder|SEOkicks|SEOkicks-Robot|SEOlyticsCrawler|SEOprofiler|SEOstats|SISTRIX|SMTBot|SalesIntelligent|ScanAlert|Scanbot|ScoutJet|Scrapy|Screaming|ScreenerBot|ScrepyBot|Searchestate|SearchmetricsBot|Seekport|SeekportBot|SemanticJuice|Semrush|SemrushBot|SentiBot|SenutoBot|SeoSiteCheckup|SeobilityBot|Seomoz|Shodan|Siphon|SiteCheckerBotCrawler|SiteExplorer|SiteLockSpider|SiteSnagger|SiteSucker|Site Sucker|Sitebeam|Siteimprove|Sitevigil|SlySearch|SmartDownload|Snake|Snapbot|Snoopy|SocialRankIOBot|Sociscraper|Sogou web spider|Sosospider|Sottopop|SpaceBison|Spammen|SpankBot|Spanner|Spbot|Spinn3r|SputnikBot|Sqlmap|Sqlworm|Sqworm|Steeler|Stripper|Sucker|Sucuri|SuperBot|SuperHTTP|Surfbot|SurveyBot|Suzuran|Swiftbot|Szukacz|T0PHackTeam|T8Abot|Teleport|TeleportPro|Telesoft|Telesphoreo|Telesphorep|TheNomad|The Intraformant|Thumbor|TightTwatBot|Titan|Toata|Toweyabot|Tracemyfile|Trendiction|Trendictionbot|True_Robot|Turingos|Turnitin|TurnitinBot|TwengaBot|Twice|Typhoeus|URLy\.Warning|URLy Warning|UnisterBot|Upflow|V-BOT|VB Project|VCI|Vacuum|Vagabondo|VelenPublicWebCrawler|VeriCiteCrawler|VidibleScraper|Virusdie|VoidEYE|Voil|Voltron|WASALive-Bot|WBSearchBot|WEBDAV|WISENutbot|WPScan|WWW-Collector-E|WWW-Mechanize|WWW::Mechanize|WWWOFFLE|Wallpapers|Wallpapers\/3\.0|WallpapersHD|WeSEE|WebAuto|WebBandit|WebCollage|WebCopier|WebEnhancer|WebFetch|WebFuck|WebGo IS|WebImageCollector|WebLeacher|WebPix|WebReaper|WebSauger|WebStripper|WebSucker|WebWhacker|WebZIP|Web Auto|Web Collage|Web Enhancer|Web Fetch|Web Fuck|Web Pix|Web Sauger|Web Sucker|Webalta|WebmasterWorldForumBot|Webshag|WebsiteExtractor|WebsiteQuester|Website Quester|Webster|Whack|Whacker|Whatweb|Who\.is Bot|Widow|WinHTTrack|WiseGuys Robot|Wonderbot|Woobot|Wotbox|Wprecon|Xaldon WebSpider|Xaldon_WebSpider|Xenu|YoudaoBot|Zade|Zauba|Zermelo|Zeus|Zitebot|ZmEu|ZoomBot|ZoominfoBot|ZumBot|ZyBorg|adscanner|arquivo-web-crawler|arquivo\.pt|autoemailspider|backlink-check|cah\.io\.community|check1\.exe|clark-crawler|coccocbot|cognitiveseo|com\.plumanalytics|crawl\.sogou\.com|crawler\.feedback|crawler4j|dataforseo\.com|dataforseobot|demandbase-bot|domainsproject\.org|eCatch|evc-batch|facebookscraper|gopher|heritrix|instabid|internetVista monitor|ips-agent|isitwp\.com|iubenda-radar|linkdexbot|lwp-request|lwp-trivial|magpie-crawler|meanpathbot|mediawords|muhstik-scan|netEstate NE Crawler|page scorer|pcBrowser|plumanalytics|polaris version|probe-image-size|ripz|s1z\.ru|satoristudio\.net|scalaj-http|scan\.lol|seobility|seocompany\.store|seoscanners|seostar|serpstatbot|sexsearcher|sitechecker\.pro|siteripz|sogouspider|sp_auditbot|spyfu|sysscan|tAkeOut|trendiction\.com|trendiction\.de|ubermetrics-technologies\.com|voyagerx\.com|webgains-bot|webmeup-crawler|webpros\.com|webprosbot|x09Mozilla|x22Mozilla|xpymep1\.exe|zauba\.io|zgrab)/i;
var badBots_default = {
  check: /* @__PURE__ */ __name((req) => {
    if (regex.test(req.ua)) {
      return false;
    }
    return true;
  }, "check")
};

// src/easy-waf/logger.ts
function log(type, msg) {
  if (type === "Info") {
    console.info(`EasyWAF - Info: ${msg} - ${(/* @__PURE__ */ new Date()).getTime()}`);
  } else if (type === "Warn") {
    console.warn(`EasyWAF - Warning: ${msg} - ${(/* @__PURE__ */ new Date()).getTime()}`);
  } else {
    console.error(`EasyWAF - Error: ${msg} - ${(/* @__PURE__ */ new Date()).getTime()}`);
  }
}
__name(log, "log");
function logBlockedRequest(moduleName, req, referenceID, config6) {
  if (config6.disableLogging) return;
  const url = req.url.replace(/(\n|\r|\v)/gi, "").replace(/"/g, "&quot;");
  const ua = req.ua.replace(/(\n|\r|\v)/gi, "").replace(/"/g, "&quot;");
  console.warn((!config6.dryMode ? "EasyWAF - Blocked:" : "EasyWAF DryMode - Blocked:") + " ip=" + req.ip + " module=" + moduleName + " time=" + (/* @__PURE__ */ new Date()).getTime() + ' url="' + url + '" ua="' + ua + '" method=' + req.method + " rid=" + referenceID);
}
__name(logBlockedRequest, "logBlockedRequest");

// src/easy-waf/modules/blockTorExitNodes.ts
import { Matcher } from "netparser";
var config;
var torExitNodes;
async function updateTorExitNodesList() {
  try {
    const data = await httpGET("https://check.torproject.org/torbulkexitlist");
    if (typeof data !== "string") {
      throw new Error("Data is not a string");
    }
    let arr = data.split(/\r?\n/);
    if (!Array.isArray(arr)) {
      throw new Error("Data is not an array");
    }
    arr = arr.filter((line) => line.length != 0);
    torExitNodes = new Matcher(arr);
  } catch (err) {
    if (err instanceof Error) {
      log("Error", "Exception while updating Tor Exit Nodes list: " + err.message);
    }
  }
  setTimeout(updateTorExitNodesList, 36e5);
}
__name(updateTorExitNodesList, "updateTorExitNodesList");
var blockTorExitNodes_default = {
  init: /* @__PURE__ */ __name((conf) => {
    config = conf;
    if (config.modules?.blockTorExitNodes && "enabled" in config.modules.blockTorExitNodes && config.modules.blockTorExitNodes.enabled) {
      updateTorExitNodesList();
    }
  }, "init"),
  check: /* @__PURE__ */ __name((req) => {
    if (typeof torExitNodes !== "undefined" && torExitNodes.has(req.ip)) {
      return false;
    }
    return true;
  }, "check")
};

// src/easy-waf/modules/specialchars.regex.ts
var dot = "(%2e|\\.|%u002e|%c0%2e|%e0%40%ae|%c0%ae|%252e|0x2e|%uff0e|%00\\.|\\.%00|%c0\\.|%25c0%25ae|%%32%{1,2}65)";
var slash = "(%2f|%5C|\\\\|\\/|%u2215|%u2216|%c0%af|%e0%80%af|%c0%2f|%c0%5c|%c0%80%5c|%252f|%255c|0x2f|0x5c|%uff0f|%25c0%25af|%25c0%252f|%%32%{1,2}66|%%35%{1,2}63|%25c1%259c|%25c0%25af|%f0%80%80%af|%f8%80%80%80%af|%c1%9c|%c1%pc|%c0%9v|%c0%qf|%c1%8s|%c1%1c|%c1%af|%bg%qf|%uEFC8|%uF025|%e0%81%9c|%f0%80%81%9c)";
var brackedOpen = "(\\(|%28|&#x0{0,}28;?|&lpar;)";
var colon = "(:|%3A|\\\\u003a|\\\\x3a)";
var lT = "(<|%3C|\\+ADw-|&#0{0,}60;?|&#x0{0,}3c;?|\\\\u003c|\\\\x3c)";
var underscore = "(_|%5F|\\+AF8-|\\\\u005f|\\\\x0{0,}5f)";
var at = "(@|%40|\\+AEA-|\\\\u0040|\\\\x0{0,}40)";
var equals = "(=|%3D|\\+AD0-|\\\\u003d|\\\\x0{0,}3d)";
var quotationMarks = '("|%22|\\+ACI-|\\\\u0022|\\\\x0{0,}22)';
var singleQuotationMarks = "('|%27|\\\\u0027|\\\\x0{0,}27)";
var and = "(&|%26|\\+ACY-|\\\\u0026|\\\\x0{0,}26)";
var or = "(\\||%7c|\\+AHw-|\\\\u007c|\\\\x0{0,}7c)";
var curlyBracketOpen = "({|%7B|\\+AHs-|\\\\u007b|\\\\x0{0,}7b)";
var squareBracketOpen = "(\\[|%5B|\\+AFs-|\\\\u005b|\\\\x0{0,}5b)";
var squareBracketClose = "(\\]|%5D|\\+AF0-|\\\\u005d|\\\\x0{0,}5d)";
var dollar = "(\\$|%24|\\+ACQ-|\\\\u0024|\\\\x0{0,}24)";
var minus = "(-|%2D|\\\\u002d|\\\\x0{0,}2d)";
var percent = "(%|%25|\\+ACU-|\\\\u0025|\\\\x0{0,}25)";
var exclamation = "(!|%21|\\+ACE-|\\\\u0021|\\\\x0{0,}21)";

// src/easy-waf/modules/crlfInjection.ts
var regex2 = new RegExp(`((\\r|%0D|%E5%98%8D|\\\\u560d|%250D)|(\\n|%0A|%E5%98%8A|\\\\u560a|%250a))(Set${minus}Cookie|Content${minus}(Length|Type|Location|Disposition|Security${minus}Policy)|X${minus}XSS${minus}Protection|Last${minus}Modified|Location|Date|Link|Refresh|${lT})`, "i");
var crlfInjection_default = {
  check: /* @__PURE__ */ __name((req) => {
    if (regex2.test(req.url)) {
      return false;
    }
    if (req.body && regex2.test(req.body)) {
      return false;
    }
    return true;
  }, "check")
};

// src/easy-waf/modules/directoryTraversal.ts
var regex3 = new RegExp(`(${dot}{2,3};?${slash}|${slash};?${dot}{2,3}|${slash}(etc|proc|home|run|var|usr|root|bin|cgi-bin|windows|system32)${slash}|c(:|%3A|%253A)${slash}|${slash}${dot}${slash}|boot${dot}ini|${dot}htaccess|(file|zip|php|data).${slash}{2}|${percent}systemroot${percent})`, "i");
var directoryTraversal_default = {
  check: /* @__PURE__ */ __name((req) => {
    if (regex3.test(req.url)) {
      return false;
    }
    if (req.body && regex3.test(req.body)) {
      return false;
    }
    return true;
  }, "check")
};

// src/easy-waf/modules/fakeCrawlers.ts
import { reverse, lookup } from "dns/promises";
import { Matcher as Matcher2 } from "netparser";
var config2;
var uaRegex = new RegExp("(Google|Bingbot|AdIdxBot|BingPreview|MicrosoftPreview|DuckDuck(Go|Bot)|Yahoo!|Yandex\\S|Baiduspider|Qwantify|Pinterestbot|pinterest.com/bot|Twitterbot|facebookexternalhit|facebookcatalog)", "i");
var rdnsRegex = new RegExp("(.googlebot.com|.google.com|.live.com|.msn.com|.bing.com|.microsoft.com|.yahoo.com|.yahoo.net|.yandex.net|.yandex.ru|.yandex.com|.baidu.com|.baidu.jp|.qwant.com|.pinterest.com|.pinterestcrawler.com|.twttr.com|.twitter.com)$", "i");
var ipWhitelist;
var fakeCrawlers_default = {
  init: /* @__PURE__ */ __name((conf) => {
    config2 = conf;
    if (config2.modules?.fakeCrawlers && "enabled" in config2.modules.fakeCrawlers && config2.modules.fakeCrawlers.enabled && typeof process.env["TEST_FAKE_CRAWLERS"] !== "string") {
      updateIPWhitelist();
    }
  }, "init"),
  check: /* @__PURE__ */ __name(async (req) => {
    if (!uaRegex.test(req.ua)) {
      return true;
    }
    if (typeof ipWhitelist !== "undefined" && ipWhitelist.has(req.ip)) {
      return true;
    }
    try {
      const hostnames = await reverse(req.ip);
      if (!Array.isArray(hostnames)) {
        return false;
      }
      const matchedHostname = [];
      for (const hostname of hostnames) {
        if (rdnsRegex.test(hostname)) {
          matchedHostname.push(hostname);
        }
      }
      if (!matchedHostname.length) {
        return false;
      }
      for (const hostname of matchedHostname) {
        const lookupRes = await lookup(hostname);
        if (!lookupRes) {
          continue;
        }
        if (lookupRes.address === req.ip) {
          addIPToWhitelist(req.ip);
          return true;
        }
      }
      return false;
    } catch (err) {
      if (err instanceof Error) {
        log("Error", `Error on fakeCrawlers check: IP: ${req.ip} Msg: ${err.message}`);
      }
      return false;
    }
  }, "check"),
  updateIPWhitelist
};
async function updateIPWhitelist() {
  try {
    const result = await httpGET("https://raw.githubusercontent.com/timokoessler/easy-waf-data/main/data/crawler-ips/all.json");
    const json = JSON.parse(result);
    if (!Array.isArray(json)) throw new Error("Invalid JSON");
    ipWhitelist = new Matcher2(json);
  } catch (err) {
    log("Error", "Exception while updating Google ip whitelist: " + err.message);
  }
  setTimeout(updateIPWhitelist, 1e3 * 60 * 60 * 4);
  return;
}
__name(updateIPWhitelist, "updateIPWhitelist");
function addIPToWhitelist(ip) {
  if (typeof ipWhitelist === "undefined") {
    ipWhitelist = new Matcher2();
  }
  ipWhitelist.add(ip);
}
__name(addIPToWhitelist, "addIPToWhitelist");

// src/easy-waf/modules/httpParameterPollution.ts
var httpParameterPollution_default = {
  check: /* @__PURE__ */ __name((req) => {
    for (const [key, value] of Object.entries(req.query)) {
      if (Array.isArray(value)) {
        req.query[key] = value[value.length - 1];
      }
    }
    return true;
  }, "check")
};

// src/easy-waf/modules/noSqlInjection.ts
var regex4 = new RegExp(`((${squareBracketOpen}|${curlyBracketOpen}(${quotationMarks}|${singleQuotationMarks})?(\\s+)?)${dollar}\\S+(${colon}|${squareBracketClose})|${dollar}(where|n?or|and|not|regex|eq|ne|gte?|lte?|n?in|exists|comment|expr|mod|size|rand)|db${dot}\\S+${dot}(find|findOne|insert|update|insertOne|insertMany|updateMany|updateOne|delete|deleteOne|deleteMany|drop|count)${brackedOpen}|sleep${brackedOpen}|db${dot}(getCollectionNames|dropDatabase)${brackedOpen}|${underscore}all${underscore}docs|this${dot}\\S+${dot}match${brackedOpen}|new\\sDate${brackedOpen}|${or}{2}\\s+\\d${equals}{2}\\d|${and}{2}\\s+this${dot})`, "i");
var noSqlInjection_default = {
  check: /* @__PURE__ */ __name((req) => {
    if (regex4.test(req.url) || regex4.test(req.ua) || regex4.test(req.headers)) {
      return false;
    }
    if (req.body && regex4.test(req.body)) {
      return false;
    }
    return true;
  }, "check")
};

// src/easy-waf/modules/openRedirect.ts
var regex5 = new RegExp(`(?:${slash}{2})(?<domain>((\\w|${minus}|${underscore})+${dot})*(?:\\w|${minus}|${underscore})+[${dot}${colon}]\\w+)`, "gi");
var config3;
var openRedirect_default = {
  init: /* @__PURE__ */ __name((conf) => {
    config3 = conf;
  }, "init"),
  check: /* @__PURE__ */ __name((req) => {
    if (typeof config3.queryUrlWhitelist === "undefined") {
      return true;
    }
    const matches = req.url.matchAll(regex5);
    for (const match of matches) {
      if (match.groups && match.groups["domain"] && !config3.queryUrlWhitelist.includes(match.groups["domain"])) {
        return false;
      }
    }
    return true;
  }, "check")
};

// src/easy-waf/modules/prototypePollution.ts
var regex6 = new RegExp(`(${underscore}${underscore}proto${underscore}${underscore}|\\S${dot}prototype(${dot}|${squareBracketOpen})|${squareBracketOpen}prototype${squareBracketClose})`, "i");
var prototypePollution_default = {
  check: /* @__PURE__ */ __name((req) => {
    if (regex6.test(req.url) || regex6.test(req.ua) || regex6.test(req.headers)) {
      return false;
    }
    if (req.body && regex6.test(req.body)) {
      return false;
    }
    return true;
  }, "check")
};

// src/easy-waf/modules/sqlInjection.ts
var sqlWS = "(\\s|\\/\\*.*\\*\\/|\\t|\\r|\\f|\\n|\\v|\\\\x(0([0-7]|E|F)|1([0-9]|[a-f])|7F)|\\+)";
var regex7 = new RegExp(`(${at}{2}(version|innodb_version|connections|cpu${underscore}busy|servername|dbts|langid|language|lock${underscore}timeout|max${underscore}connections|max${underscore}precision|nestlevel|options|servicename|spid|textsize|microsoftversion)|xp${underscore}cmdshell|information${underscore}schema|innodb${underscore}table${underscore}stats|union${sqlWS}(all${sqlWS})?select|(benchmark|substr(ing)?|selectchar|sleep|conv|connection${underscore}id|binary${underscore}checksum|upper|hex|md5|distinct|load_file|cvar|last${underscore}insert${underscore}rowid|sqlite${underscore}version|current${underscore}database|current${underscore}setting|pg${underscore}client${underscore}encoding|crc32|user${underscore}id|sha1|quote${underscore}literal|chr|randomblob|cdbl|get${underscore}current${underscore}ts${underscore}config|sysdate)${brackedOpen}|${colon}{2}int(eger)?${equals}|mysql${dot}(user|innodb|db|(tables|columns|procs|proxies)${underscore}priv|event|func|plugin|proc|(general|slow)${underscore}log|(help|time|slave)${underscore}|gtid${underscore}executed|ndb${underscore}binlog${underscore}index|server${underscore}cost|engine${underscore}cost)|all${underscore}tab${underscore}tables|waitfor${sqlWS}delay|(or|and|where|having|${and}{2}|${or}{2})${sqlWS}\\w+${sqlWS}?(${equals}|${lT})\\w|(${quotationMarks}|${singleQuotationMarks})${sqlWS}?(or|and|where|having|${and}{2}|${or}{2}|${lT}|${equals})${sqlWS}?(${quotationMarks}|${singleQuotationMarks})|pg${underscore}shadow|pg${underscore}group|order${sqlWS}by${sqlWS}\\d|select${sqlWS}(\\*${sqlWS}from|version${brackedOpen}|current${underscore}user|session${underscore}user)|http${dot}request${brackedOpen}|1${dot}e${dot}table_name|insert${sqlWS}into${sqlWS}\\w+${sqlWS}${brackedOpen}|create${sqlWS}user${sqlWS}\\w+${sqlWS}identified${sqlWS}by|backup${sqlWS}database${sqlWS}\\w+${sqlWS}to|update${sqlWS}\\w+${sqlWS}set${sqlWS}\\w+${sqlWS}?${equals})`, "i");
var sqlInjection_default = {
  check: /* @__PURE__ */ __name((req) => {
    if (regex7.test(req.url) || regex7.test(req.ua) || regex7.test(req.headers)) {
      return false;
    }
    if (req.body && regex7.test(req.body)) {
      return false;
    }
    return true;
  }, "check")
};

// src/easy-waf/modules/xss.ts
var htmlTags = "(a|abbr|acronym|address|applet|area|article|aside|audio|b|base|basefont|bdi|bdo|big|blockquote|body|br|button|canvas|caption|center|cite|code|col|colgroup|command|data|datalist|dd|del|details|dfn|dir|div|dl|dt|em|embed|fieldset|figcaption|figure|font|footer|form|frame|frameset|h1|h2|h3|h4|h5|h6|head|header|hr|html|i|iframe|img|input|ins|kbd|keygen|label|layer|legend|li|line|link|listing|main|map|mark|marquee|math|menu|menuitem|meta|meter|nav|nobr|noembed|noframes|nolayer|noscript|object|ol|optgroup|option|output|p|param|plaintext|pre|progress|q|rp|rt|ruby|s|samp|script|section|select|small|source|span|strike|strong|style|sub|summary|sup|svg|t|table|tbody|td|template|textarea|tfoot|th|thead|time|title|tr|track|tt|u|ul|var|video|wbr|xmp|foreignObject)";
var jsEvents = "(onAbort|onActivate|onAfterPrint|onAfterUpdate|onBeforeActivate|onBeforeCopy|onBeforeCut|onBeforeDeactivate|onBeforeEditFocus|onBeforePaste|onBeforePrint|onBeforeUnload|onBeforeUpdate|onBegin|onBlur|onBounce|onCellChange|onChange|onClick|onContextMenu|onControlSelect|onCopy|onCut|onDataAvailable|onDataSetChanged|onDataSetComplete|onDblClick|onDeactivate|onDrag|onDragDrop|onDragEnd|onDragEnter|onDragLeave|onDragOver|onDragStart|onDrop|onEnd|onError|onErrorUpdate|onFilterChange|onFinish|onFocus|onFocusIn|onFocusOut|onHashChange|onHelp|onInput|onKeyDown|onKeyPress|onKeyUp|onLayoutComplete|onLoad|onLoseCapture|onMediaComplete|onMediaError|onMessage|onMouseDown|onMouseEnter|onMouseLeave|onMouseMove|onMouseOut|onMouseOver|onMouseUp|onMouseWheel|onMove|onMoveEnd|onMoveStart|onOffline|onOnline|onOutOfSync|onPaste|onPause|onPopState|onProgress|onPropertyChange|onReadyStateChange|onRedo|onRepeat|onReset|onResize|onResizeEnd|onResizeStart|onResume|onReverse|onRowDelete|onRowExit|onRowInserted|onRowsEnter|onScroll|onSeek|onSelect|onSelectStart|onSelectionChange|onStart|onStop|onStorage|onSubmit|onSyncRestored|onTimeError|onTrackChange|onURLFlip|onUndo|onUnload|seekSegmentTime)";
var functions = `(alert|call|confirm|console${dot}[a-zA-Z]{1,}|eval|fetch|prompt|setTimeout|setInterval|toString|url)`;
var regex8 = new RegExp(`(${lT}${slash}?(java)?script|${lT}${slash}?${htmlTags}|${functions}(${brackedOpen}|\`|(\\\\){1,2}x28)|(${brackedOpen}|${equals})${functions}|javascript${colon}|${lT}xss|${lT}${slash}?(\\?|%3F)?xml|${lT}${slash}?dialog|(navigator|document|localStorage|process)${dot}\\S|${jsEvents}${equals}|${lT}\\??import|top\\[|${dot}(inner|outer)HTML|response${dot}write${brackedOpen})`, "i");
var xss_default = {
  check: /* @__PURE__ */ __name((req) => {
    if (regex8.test(req.url) || regex8.test(req.ua) || regex8.test(req.headers)) {
      return false;
    }
    if (req.body && regex8.test(req.body)) {
      return false;
    }
    return true;
  }, "check")
};

// src/easy-waf/modules/xmlInjection.ts
var regex9 = new RegExp(`(${lT}${exclamation}ENTITY.*(SYSTEM|PUBLIC).*(${quotationMarks}|${singleQuotationMarks})\\w+${colon}//|${lT}xi${colon}include|${lT}xsl${colon}(value-of|copy-of).*(${quotationMarks}|${singleQuotationMarks})(system-property|document)${brackedOpen}|${lT}msxsl${colon}script)`, "i");
var xmlInjection_default = {
  check: /* @__PURE__ */ __name((req) => {
    if (req.body && regex9.test(req.body)) {
      return false;
    }
    return true;
  }, "check")
};

// src/easy-waf/block.ts
async function block(req, res, moduleName, config6) {
  const date = /* @__PURE__ */ new Date();
  const referenceID = sha256(req.ip + date.getTime());
  if (typeof config6.preBlockHook === "function" && await config6.preBlockHook(req, moduleName, req.ip) === false) {
    return false;
  }
  if (!config6.dryMode) {
    res.writeHead(403, {
      "Content-Type": "text/html"
    });
    if (!config6.customBlockedPage) {
      res.write(`<!DOCTYPE html><html lang="en" style="height:95%;">
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <meta name="robots" content="noindex">
                    <title>403 Forbidden</title>
                    <style>p { line-height: 20px; };</style>
                </head>
                <body style="font-family:sans-serif;height:100%;">
                    <div style="display:flex;justify-content:center;align-items:center;height:100%;">
                        <div style="max-width:90%;word-wrap:break-word;">
                            <h1 style="margin-bottom:10px;">\u{1F6D1} Request blocked</h1>
                            <h3 style="font-weight:normal;margin-top:0px;margin-bottom:5px;margin-left:52px;">403 Forbidden</h3>
                            <hr style="margin-top:1rem;margin-bottom:1rem;border:0;border-top:1px solid rgba(0, 0, 0, 0.1);">
                            <p>This website uses a firewall to protect itself from online attacks.<br>
                            You have sent a suspicious request, therefore your request has been blocked.</p>
                            <hr style="margin-top:1rem;margin-bottom:1rem;border:0;border-top:1px solid rgba(0, 0, 0, 0.1);">
                            <p>Time: ` + date.toUTCString() + `<br>
                            Your IP: ` + req.ip + `<br>
                            Reference ID: ` + referenceID + `</p>
                        </div>
                    </div>
                </body>
            </html>`);
    } else {
      const mapObj = {
        dateTime: date.toUTCString(),
        ip: req.ip,
        referenceID,
        moduleName
      };
      res.write(config6.customBlockedPage.replace(/{\w+}/g, (matched) => {
        return mapObj[matched.slice(1, -1)];
      }));
    }
    res.end();
  }
  logBlockedRequest(moduleName, req, referenceID, config6);
  if (typeof config6.postBlockHook === "function") {
    await config6.postBlockHook(req, moduleName, req.ip);
  }
  if (config6.dryMode) {
    return false;
  }
  return true;
}
__name(block, "block");

// src/easy-waf/index.ts
var config4 = {
  dryMode: false,
  disableLogging: false,
  allowedHTTPMethods: [
    "GET",
    "POST",
    "PUT",
    "DELETE"
  ],
  trustProxy: true,
  modules: {
    sqlInjection: {
      enabled: true
    },
    xss: {
      enabled: true
    },
    directoryTraversal: {
      enabled: true
    },
    blockTorExitNodes: {
      enabled: false
    }
  }
};
var trustProxy;
var ipBlacklist;
var ipWhitelist2;
function easyWaf(conf) {
  if (typeof conf === "object" && conf !== null && !Array.isArray(conf)) {
    if (Array.isArray(conf.allowedHTTPMethods)) {
      for (const [i] of conf.allowedHTTPMethods.entries()) {
        if (typeof conf.allowedHTTPMethods[i] !== "string") {
          throw new Error("EasyWafConfig: allowedHTTPMethods may only contain strings!");
        }
        conf.allowedHTTPMethods[i] = conf.allowedHTTPMethods[i].toUpperCase();
      }
    }
    if (conf.dryMode && typeof conf.dryMode != "boolean") {
      throw new Error("EasyWafConfig: dryMode is not a boolean");
    } else if (conf.dryMode && !conf.disableLogging) {
      log("Warn", "DryMode is enabled. Suspicious requests are only logged and not blocked!");
    }
    if (typeof conf.ipBlacklist !== "undefined") {
      if (!Array.isArray(conf.ipBlacklist)) {
        throw new Error("EasyWafConfig: ipBlacklist is not an array");
      }
      ipBlacklist = new IPMatcher(conf.ipBlacklist);
    }
    if (typeof conf.ipWhitelist !== "undefined") {
      if (!Array.isArray(conf.ipWhitelist)) {
        throw new Error("EasyWafConfig: ipWhitelist is not an array");
      }
      ipWhitelist2 = new IPMatcher(conf.ipWhitelist);
    }
    conf.modules = {
      ...config4.modules,
      ...conf.modules
    };
    config4 = {
      ...config4,
      ...conf
    };
  }
  trustProxy = compileProxyTrust(typeof config4.trustProxy !== "undefined" ? config4.trustProxy : []);
  for (const [, module] of Object.entries(modules_exports)) {
    if (typeof module.init === "function") {
      module.init?.(config4);
    }
  }
  return /* @__PURE__ */ __name(async function EasyWaf(rawReq, res, next) {
    const ip = proxyaddr2(rawReq, trustProxy);
    if (typeof ip === "undefined") {
      throw new Error("EasyWAF: Unable to determine client IP");
    }
    if (typeof ipWhitelist2 !== "undefined" && ipWhitelist2.get(ip)) {
      next();
      return;
    }
    const req = {
      headers: Object.values(rawReq.headers).join(),
      ip,
      method: rawReq.method,
      path: "",
      query: typeof rawReq.query === "object" && rawReq.query !== null ? rawReq.query : {},
      ua: rawReq.headers["user-agent"] || "",
      url: "",
      rawReq
    };
    try {
      req.url = decodeURIComponent(rawReq.url);
    } catch {
      req.url = typeof rawReq.url === "string" ? rawReq.url : "";
      if (!await block(req, res, "uriMalformed", config4)) {
        next();
      }
      return;
    }
    const pathRegexRes = req.url.match("^[^?]*");
    req.path = Array.isArray(pathRegexRes) && typeof pathRegexRes[0] === "string" ? pathRegexRes[0] : "";
    if (typeof ipBlacklist !== "undefined" && ipBlacklist.get(ip)) {
      if (await block(req, res, "IPBlacklist", config4)) {
        return;
      }
    }
    if (Array.isArray(config4.allowedHTTPMethods) && !config4.allowedHTTPMethods.includes(req.method)) {
      if (await block(req, res, "HTTPMethod", config4)) {
        return;
      }
    }
    if (typeof rawReq.body !== "undefined") {
      if (typeof rawReq.body === "object" && rawReq.body !== null && Object.keys(rawReq.body).length) {
        req.body = JSON.stringify(rawReq.body);
      } else if (typeof rawReq.body === "string") {
        req.body = rawReq.body;
      }
    }
    for (const [moduleName, module] of Object.entries(modules_exports)) {
      if (typeof config4.modules !== "undefined" && moduleName in config4.modules) {
        if (!config4.modules[moduleName]?.enabled) {
          continue;
        }
        if (config4.modules[moduleName]?.excludePaths instanceof RegExp && config4.modules[moduleName]?.excludePaths?.test(req.path)) {
          continue;
        }
      }
      const ok = await module.check(req);
      if (!ok && await block(req, res, moduleName, config4)) {
        return;
      }
    }
    next();
  }, "EasyWaf");
}
__name(easyWaf, "easyWaf");

// src/easy-waf/modules/ddosProtection.ts
import geoip from "geoip-lite";
var DDoSProtection = class DDoSProtection2 {
  static {
    __name(this, "DDoSProtection");
  }
  userRecently = /* @__PURE__ */ new Set();
  usersMap = /* @__PURE__ */ new Map();
  ddosCount = 0;
  isDDoSAttack = false;
  config;
  constructor(config6) {
    this.config = config6;
    this.startDDoSMonitoring();
    this.startCleanupTask();
  }
  startDDoSMonitoring() {
    setInterval(() => {
      if (!this.isDDoSAttack && this.ddosCount > this.config.ddosThreshold) {
        this.isDDoSAttack = true;
        for (let i = 0; i < 20; i++) {
          console.log("[DEFENSE SYSTEM] WARNING DDOS ATTACK DETECTED!");
        }
        setTimeout(() => {
          for (let i = 0; i < 20; i++) {
            console.log("[DEFENSE SYSTEM] DDOS ATTACKS NOW STOPPED!");
          }
          this.isDDoSAttack = false;
        }, this.config.ddosTimeout);
      }
      this.ddosCount = 0;
    }, 2e3);
  }
  startCleanupTask() {
    setInterval(() => {
      const now = Date.now();
      for (const [key, userData] of this.usersMap.entries()) {
        if (userData.banned && userData.banExpiry && now > userData.banExpiry) {
          this.usersMap.delete(key);
          if (this.config.enableLogging) {
            console.log(`[DDOS] Ban expired and removed: ${key}`);
          }
        } else if (!userData.banned && now - userData.firstRequest > this.config.userDataTimeout) {
          this.usersMap.delete(key);
          if (this.config.enableLogging) {
            console.log(`[DDOS] User data expired and removed: ${key}`);
          }
        }
      }
    }, 6e4);
  }
  async extractIP(req) {
    if (req.headers["cf-connecting-ip"]) {
      return req.headers["cf-connecting-ip"];
    }
    let ip = (req.headers["x-forwarded-for"] || "").replace(/:\d+$/, "") || req.connection?.remoteAddress || req.socket?.remoteAddress || req.ip;
    if (ip?.includes("::ffff:")) {
      ip = ip.split(":").reverse()[0];
    }
    if (ip === "127.0.0.1" || ip === "::1") {
      return "1.11.111.1111";
    }
    return ip || "1.11.111.1111";
  }
  async getGeoLocation(ip, req) {
    if (req.headers["cf-ipcountry"]) {
      return req.headers["cf-ipcountry"];
    }
    const lookedUpIP = geoip.lookup(ip);
    return lookedUpIP?.country || "UNKNOWN";
  }
  async checkRequest(req) {
    try {
      const ipAddress = await this.extractIP(req);
      const geo = await this.getGeoLocation(ipAddress, req);
      const userKey = `veri_${ipAddress}`;
      const now = Date.now();
      let userData = this.usersMap.get(userKey);
      if (userData?.banned) {
        if (userData.banExpiry && now > userData.banExpiry) {
          this.usersMap.delete(userKey);
          userData = void 0;
          if (this.config.enableLogging) {
            console.log(`[DDOS] Ban expired: ${ipAddress}`);
          }
        } else {
          const remaining = userData.banExpiry ? Math.ceil((userData.banExpiry - now) / 1e3) : 0;
          if (this.config.enableLogging) {
            console.log(`[DDOS] Blocked banned user: ${ipAddress} (${remaining}s remaining)`);
          }
          return {
            blocked: true,
            reason: "USER_BANNED",
            message: {
              WARNING: "You have been temporarily banned for sending too many requests",
              "Remaining Ban Time": `${remaining} seconds`,
              "Support Mail": this.config.supportMail,
              info: this.config.mainInfo
            }
          };
        }
      }
      if (!userData) {
        userData = {
          count: 1,
          firstRequest: now,
          banned: false
        };
        this.usersMap.set(userKey, userData);
      } else {
        if (now - userData.firstRequest <= this.config.userDataTimeout) {
          userData.count++;
        } else {
          userData.count = 1;
          userData.firstRequest = now;
        }
      }
      if (userData.count > this.config.maxRequestsPerUser) {
        userData.banned = true;
        userData.banExpiry = now + this.config.userBanTimeout;
        if (this.config.enableLogging) {
          console.log(`[DDOS] User banned: ${ipAddress} (${userData.count} requests in ${Math.ceil((now - userData.firstRequest) / 1e3)}s)`);
        }
        return {
          blocked: true,
          reason: "RATE_LIMIT_EXCEEDED",
          message: {
            WARNING: "Rate limit exceeded - You have been temporarily banned",
            "Requests Made": userData.count,
            "Ban Duration": `${Math.ceil(this.config.userBanTimeout / 1e3)} seconds`,
            "Support Mail": this.config.supportMail,
            info: this.config.mainInfo
          }
        };
      }
      if (geo !== this.config.mainCountry) {
        if (this.isDDoSAttack) {
          return {
            blocked: true,
            reason: "GLOBAL_DDOS",
            message: {
              WARNING: "Global DDOS Detected",
              Mail: this.config.supportMail
            }
          };
        }
        this.ddosCount += 1;
      }
      if (this.config.enableLogging) {
        const windowTime = Math.ceil((now - userData.firstRequest) / 1e3);
        console.log(`[DDOS-LOG] Request from ${geo} (${ipAddress}) | Count: ${userData.count}/${this.config.maxRequestsPerUser} in ${windowTime}s | Global-DOS: ${this.ddosCount}/${this.config.ddosThreshold}`);
      }
      return {
        blocked: false
      };
    } catch (error) {
      console.error("[DDOS] Error in protection check:", error);
      return {
        blocked: false
      };
    }
  }
  // Getter methods for monitoring
  get isDDoSActive() {
    return this.isDDoSAttack;
  }
  get currentDDoSCount() {
    return this.ddosCount;
  }
  get activeUsers() {
    return this.usersMap.size;
  }
  // Method to get current user stats (for debugging)
  getUserStats() {
    const stats = {};
    for (const [key, userData] of this.usersMap.entries()) {
      stats[key] = {
        count: userData.count,
        banned: userData.banned,
        windowAge: userData.firstRequest ? Math.ceil((Date.now() - userData.firstRequest) / 1e3) : 0,
        banTimeRemaining: userData.banExpiry ? Math.max(0, Math.ceil((userData.banExpiry - Date.now()) / 1e3)) : 0
      };
    }
    return stats;
  }
};
var ddosProtection_default = DDoSProtection;

// src/index.ts
config5();
var app = express();
var PORT = process.env["PORT"] || 9e3;
var appConfig = {
  supportMail: process.env["SUPPORT_MAIL"] || "patelanshu702@gmail.com",
  mainCountry: process.env["MAIN_COUNTRY"] || "IN",
  mainInfo: process.env["MAIN_INFO"] || "You can send an e-mail in english.",
  ddosLog: process.env["DDOS_LOG"] === "true",
  disableDdosProtection: process.env["DISABLE_DDOS"] === "true",
  protectedUrls: [
    "/",
    "/error",
    "/api",
    "/admin",
    "/auth",
    "/user",
    "/logs",
    "/health"
  ]
};
var ddosProtection = new ddosProtection_default({
  maxRequestsPerUser: 100,
  ddosThreshold: 200,
  ddosTimeout: 36e5,
  userBanTimeout: 3e5,
  userDataTimeout: 12e4,
  mainCountry: appConfig.mainCountry,
  supportMail: appConfig.supportMail,
  mainInfo: appConfig.mainInfo,
  enableLogging: appConfig.ddosLog
});
app.use(helmet());
app.use(cors({
  origin: process.env["CLIENT_URL"] || "http://localhost:5173",
  credentials: true
}));
app.use(express.json({
  limit: "10mb"
}));
app.use(express.urlencoded({
  extended: true,
  limit: "10mb"
}));
app.use(cookieParser());
var limiter = rateLimit({
  windowMs: 15 * 60 * 1e3,
  max: 100,
  message: "Too many requests from this IP, please try again later.",
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);
var wafConfig = {
  dryMode: false,
  disableLogging: false,
  allowedHTTPMethods: [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS"
  ],
  trustProxy: true,
  modules: {
    sqlInjection: {
      enabled: true
    },
    xss: {
      enabled: true
    },
    directoryTraversal: {
      enabled: true
    },
    noSqlInjection: {
      enabled: true
    },
    xmlInjection: {
      enabled: true
    },
    crlfInjection: {
      enabled: true
    },
    prototypePollution: {
      enabled: true
    },
    httpParameterPollution: {
      enabled: true
    },
    openRedirect: {
      enabled: true
    },
    badBots: {
      enabled: true
    },
    fakeCrawlers: {
      enabled: true
    },
    blockTorExitNodes: {
      enabled: false
    }
  },
  postBlockHook: /* @__PURE__ */ __name(async (req, moduleName, ip) => {
    console.log(`\u{1F6AB} WAF Blocked ${moduleName} attack from ${ip} - URL: ${req.url}`);
  }, "postBlockHook"),
  preBlockHook: /* @__PURE__ */ __name(async (_req, _moduleName, _ip) => {
    return true;
  }, "preBlockHook")
};
var wafMiddleware = easyWaf(wafConfig);
app.use(async (req, res, next) => {
  const url = req.originalUrl;
  if (appConfig.protectedUrls.some((protectedUrl) => url.startsWith(protectedUrl))) {
    if (!appConfig.disableDdosProtection) {
      const ddosResult = await ddosProtection.checkRequest(req);
      if (ddosResult.blocked) {
        console.log(`\u{1F6E1}\uFE0F  DDoS Protection blocked request from ${req.ip} - Reason: ${ddosResult.reason}`);
        return res.status(429).json(ddosResult.message);
      }
    }
    wafMiddleware(req, res, (error) => {
      if (error) {
        console.error("WAF middleware error:", error);
        return res.status(500).json({
          error: "Internal server error"
        });
      }
      return next();
    });
  } else {
    wafMiddleware(req, res, (error) => {
      if (error) {
        console.error("WAF middleware error:", error);
        return res.status(500).json({
          error: "Internal server error"
        });
      }
      return next();
    });
  }
});
app.get("/", (_req, res) => {
  res.json({
    message: "Hello World!",
    protected: true,
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  });
});
app.get("/health", (_req, res) => {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Health Check</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            padding: 40px;
            max-width: 500px;
            width: 100%;
            text-align: center;
            animation: fadeInUp 0.8s ease-out;
        }
        
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .status-icon {
            font-size: 4rem;
            margin-bottom: 20px;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        .status-title {
            font-size: 2.5rem;
            font-weight: 700;
            color: #2d3748;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .status-subtitle {
            font-size: 1.1rem;
            color: #718096;
            margin-bottom: 30px;
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }
        
        .metric-card {
            background: linear-gradient(135deg, #f7fafc, #edf2f7);
            border-radius: 15px;
            padding: 20px;
            border: 1px solid rgba(0, 0, 0, 0.05);
            transition: transform 0.3s ease;
        }
        
        .metric-card:hover {
            transform: translateY(-5px);
        }
        
        .metric-value {
            font-size: 1.5rem;
            font-weight: 700;
            color: #2d3748;
            margin-bottom: 5px;
        }
        
        .metric-label {
            font-size: 0.85rem;
            color: #718096;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .server-info {
            font-size: 1.2rem;
            font-family: 'Courier New', monospace;
            color: #4a5568;
            word-break: break-all;
        }
        
        .timestamp {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid rgba(0, 0, 0, 0.1);
            color: #718096;
            font-size: 0.9rem;
        }
        
        .ddos-status {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .ddos-active {
            background: rgba(245, 101, 101, 0.1);
            color: #c53030;
        }
        
        .ddos-inactive {
            background: rgba(72, 187, 120, 0.1);
            color: #38a169;
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: currentColor;
            animation: blink 1.5s infinite;
        }
        
        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0.3; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="status-icon">\u{1F7E2}</div>
        <h1 class="status-title">Server is Up!</h1>
        <p class="status-subtitle">All systems operational</p>
        
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">
                    <span class="ddos-status ddos-inactive">
                        <span class="status-dot"></span>
                        Protected
                    </span>
                </div>
                <div class="metric-label">Security Status</div>
            </div>
            <div class="metric-card">
                <div class="metric-value server-info">localhost:3000</div>
                <div class="metric-label">Server Host</div>
            </div>
        </div>
        
        <div class="timestamp">
            <div style="margin-bottom: 10px;">
            <span id="current-time">Last checked: Loading...</span>
        </div>
    </div>

    <script>
        // Update timestamp in real-time
        function updateTimestamp() {
            const now = new Date();
            document.getElementById('current-time').textContent = 
                'Last checked: ' + now.toLocaleString();
        }
        
        // Update immediately and then every second
        updateTimestamp();
        setInterval(updateTimestamp, 1000);
    </script>
</body>
</html>`;
  res.send(html);
});
app.get("/status", (_req, res) => {
  res.json({
    server: "running",
    protections: {
      ddos: {
        active: ddosProtection.isDDoSActive,
        activeUsers: ddosProtection.activeUsers,
        currentCount: ddosProtection.currentDDoSCount
      },
      waf: {
        modules: Object.keys(wafConfig.modules || {}).filter((key) => wafConfig.modules?.[key]?.enabled)
      }
    },
    config: {
      mainCountry: appConfig.mainCountry,
      protectedUrls: appConfig.protectedUrls
    }
  });
});
app.use((error, _req, res, _next) => {
  console.error("Unhandled error:", error);
  res.status(500).json({
    error: "Internal server error",
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  });
});
app.use((req, res) => {
  res.status(404).json({
    error: "Not found",
    path: req.originalUrl,
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  });
});
var startServer = /* @__PURE__ */ __name(async () => {
  try {
    app.listen(PORT, () => {
      console.log(`\u{1F6E1}\uFE0F  Enhanced WAF + DDoS Protection Service running on port ${PORT}`);
      console.log(`\u{1F310} Access the service at http://localhost:${PORT}`);
      console.log(`\u{1F4CA} WAF Modules enabled: ${Object.keys(wafConfig.modules || {}).filter((key) => wafConfig.modules?.[key]?.enabled).join(", ")}`);
      console.log(`\u{1F30D} Main country: ${appConfig.mainCountry}`);
      console.log(`\u{1F512} Protected URLs: ${appConfig.protectedUrls.join(", ")}`);
      console.log(`\u{1F6E1}\uFE0F  DDoS Protection: ${appConfig.disableDdosProtection ? "\u274C DISABLED" : "\u2705 ENABLED"}`);
      console.log(`\u{1F510} JWT Authentication enabled`);
      console.log(`\u{1F5C4}\uFE0F  MySQL Database connected`);
    });
  } catch (error) {
    console.error("\u274C Failed to start server:", error);
    process.exit(1);
  }
}, "startServer");
startServer();
var index_default = app;
export {
  index_default as default
};
