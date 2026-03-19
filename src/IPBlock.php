<?php
/**
 * Checks to see if an IP is block from a list of IPs, Ranges or ISO countries in a database
 * @author Adam Binnersley
 */
namespace Blocking;

use DBAL\Database;
use GeoIp2\Database\Reader;

class IPBlock
{
    protected $db;
    protected $geoIP;

    protected $blocked_ip_table = 'blocked_ips';
    protected $blocked_range_table = 'blocked_ip_range';
    protected $blocked_iso_countries = 'blocked_iso_countries';

    /**
     * Verified search engine bot hostnames (used for reverse DNS verification)
     * @var array
     */
    protected $verifiedBotDomains = [
        '.googlebot.com',      // Googlebot
        '.google.com',         // Google (other services)
        '.search.msn.com',     // Bingbot
        '.crawl.yahoo.net',    // Yahoo Slurp
        '.yandex.ru',          // Yandex
        '.yandex.net',         // Yandex
        '.yandex.com',         // Yandex
        '.crawl.baidu.com',    // Baidu
        '.crawl.baidu.jp',     // Baidu
        '.duckduckgo.com',     // DuckDuckGo
    ];

    /**
     * Adds a Database instance for the class to use
     * @param Database $db This should be an instance of the database connection
     */
    public function __construct(Database $db)
    {
        $this->db = $db;
        $this->geoIP = new Reader(dirname(__FILE__).DIRECTORY_SEPARATOR.'Geo-Country.mmdb');
    }

    /**
     * Change the default table name where the IP list is located
     * @param string $table This should be the name of the table where the list of IP are located
     * @return $this
     */
    public function setBlockedIPTable($table)
    {
        if (is_string($table)) {
            $this->blocked_ip_table = filter_var($table, FILTER_SANITIZE_STRING);
        }
        return $this;
    }

    /**
     * Returns the blocked IP's database table
     * @return string
     */
    public function getBlockedIPTable()
    {
        return $this->blocked_ip_table;
    }

    /**
     * Change the default table name where the IP Range list is located
     * @param string $table This should be the name of the table where the list of IP ranges are located
     * @return $this
     */
    public function setBlockedRangeTable($table)
    {
        if (is_string($table)) {
            $this->blocked_range_table = filter_var($table, FILTER_SANITIZE_STRING);
        }
        return $this;
    }

    /**
     * Returns the blocked IP range database table
     * @return string
     */
    public function getBlockedRangeTable()
    {
        return $this->blocked_range_table;
    }

    /**
     * Change the default table name where the ISO Country list is located
     * @param string $table This should be that table name where the ISO list is located
     * @return $this
     */
    public function setBlockedISOTable($table)
    {
        if (is_string($table)) {
            $this->blocked_iso_countries = filter_var($table, FILTER_SANITIZE_STRING);
        }
        return $this;
    }

    /**
     * Returns the blocked ISO database table
     * @return string
     */
    public function getBlockedISOTable()
    {
        return $this->blocked_iso_countries;
    }

    /**
     * Checks to see if the given IP is Blocked by listing or range
     * Verified search engine bots are never blocked
     * @param string $ip This should be the IP you are checking if it is blocked
     * @return boolean If the IP is listed will return true else will return false
     */
    public function isIPBlocked($ip)
    {
        // Never block verified search engine bots
        if ($this->isVerifiedBot($ip)) {
            return false;
        }
        return ($this->isIPBlockedList($ip) || $this->isIPBlockedRange($ip) || $this->isISOBlocked($ip));
    }

    /**
     * Verifies if an IP belongs to a legitimate search engine bot
     * Uses reverse DNS lookup followed by forward DNS verification (Google's recommended method)
     * Results are cached in session to avoid repeated DNS lookups
     * @param string $ip The IP address to verify
     * @return boolean True if the IP is a verified search engine bot
     */
    public function isVerifiedBot($ip)
    {
        // Check session cache first
        $cacheKey = 'verified_bot_' . md5($ip);
        if (isset($_SESSION[$cacheKey])) {
            return $_SESSION[$cacheKey];
        }

        $isBot = false;

        // Quick check: does the User-Agent claim to be a bot?
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        if (!$this->looksLikeBot($userAgent)) {
            $_SESSION[$cacheKey] = false;
            return false;
        }

        // Perform reverse DNS lookup
        $hostname = gethostbyaddr($ip);

        // If reverse DNS fails, gethostbyaddr returns the IP
        if ($hostname !== $ip) {
            // Check if hostname matches known bot domains
            foreach ($this->verifiedBotDomains as $domain) {
                if (substr($hostname, -strlen($domain)) === $domain) {
                    // Verify with forward DNS lookup (security check)
                    $forwardIPs = gethostbynamel($hostname);
                    if ($forwardIPs && in_array($ip, $forwardIPs)) {
                        $isBot = true;
                        break;
                    }
                }
            }
        }

        // Cache the result in session
        $_SESSION[$cacheKey] = $isBot;

        return $isBot;
    }

    /**
     * Quick check if User-Agent looks like a search engine bot
     * @param string $userAgent The User-Agent string
     * @return boolean True if it looks like a bot
     */
    protected function looksLikeBot($userAgent)
    {
        $botSignatures = [
            'Googlebot',
            'Googlebot-Image',
            'Googlebot-News',
            'Googlebot-Video',
            'Mediapartners-Google',
            'AdsBot-Google',
            'Google-InspectionTool',
            'Storebot-Google',
            'bingbot',
            'msnbot',
            'Yahoo! Slurp',
            'YandexBot',
            'Baiduspider',
            'DuckDuckBot',
        ];

        foreach ($botSignatures as $signature) {
            if (stripos($userAgent, $signature) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks to see if the given IP is Blocked
     * @param string $ip This should be the IP you are checking if it is blocked
     * @return boolean If the IP is listed will return true else will return false
     */
    public function isIPBlockedList($ip)
    {
        return boolval($this->db->select($this->getBlockedIPTable(), ['ip' => $ip]));
    }

    /**
     * Checks to see if the given IP is within a blocked range
     * @param string $ip This should be the IP you are checking if it is blocked
     * @return boolean If the IP is within a blocked range will return true else will return false
     */
    public function isIPBlockedRange($ip)
    {
        $checkIP = ip2long($ip);
        return $this->db->select($this->getBlockedRangeTable(), ['ip_start' => ['<=' => $checkIP], 'ip_end' => ['>=' => $checkIP]]);
    }

    /**
     * Check to see if the ISO county of the IP is blocked
     * @param string $ip This should be the IP you are checking if it is blocked
     * @return boolean If the IP country is blocked will return true else returns false
     */
    public function isISOBlocked($ip)
    {
        return $this->db->select($this->getBlockedISOTable(), ['iso' => $this->getIPCountryISO($ip)]);
    }

    /**
     * Adds an individual IP to the blocked list
     * @param string $ip This should be the IP address that you are blocking
     * @return boolean If the IP has been successfully added will return true else return false
     */
    public function addIPtoBlock($ip)
    {
        if (!$this->isIPBlockedList($ip) && filter_var($ip, FILTER_VALIDATE_IP)) {
            return $this->db->insert($this->getBlockedIPTable(), ['ip' => $ip]);
        }
        return false;
    }

    /**
     * Removes an IP address from the blocked list
     * @param string $ip This should be that IP address that you are removing from the blocked list
     * @return boolean If the IP address is successfully removed will return true else will return false
     */
    public function removeIPFromBlock($ip)
    {
        return $this->db->delete($this->getBlockedIPTable(), ['ip' => $ip], 1);
    }

    /**
     * List all of the IP addresses blocked in the table
     * @return boolean|array An array will be return containing all blocked IP addresses if none exist will return false
     */
    public function listBlockedIPAddresses()
    {
        return $this->db->selectAll($this->getBlockedIPTable());
    }

    /**
     * Adds a IP range to block in the database where any IP between the start and end values should be blocked
     * @param string $start This should be the start of the range you wish to block e.g. 255.255.255.0
     * @param string $end This should be the end of the range you wish to block e.g. 255.255.255.255
     * @return boolean If the range is successfully added will return true else returns false
     */
    public function addRangetoBlock($start, $end)
    {
        if (filter_var($start, FILTER_VALIDATE_IP) && filter_var($end, FILTER_VALIDATE_IP) && !$this->db->select($this->getBlockedRangeTable(), ['ip_start' => ip2long($start), 'ip_end' => ip2long($end)])) {
            return $this->db->insert($this->getBlockedRangeTable(), ['ip_start' => ip2long($start), 'ip_end' => ip2long($end)]);
        }
        return false;
    }

    /**
     * Removes a blocked range from the database
     * @param int|boolean $id If you know the ID of the range you wish to remove set this else set to false
     * @param NULL|string $start If you don't know the ID of the range you want to unblock enter the IP at the start of the IP range
     * @param NULL|string $end If you don't know the ID of the range you want to unblock enter the IP at the end of the IP range
     * @return boolean If the range is removed from the database will return true else return false
     */
    public function removeRangeFromBlock($id, $start = null, $end = null)
    {
        if (is_numeric($id)) {
            $where = ['id' => $id];
        } else {
            $where = ['ip_start' => ip2long($start), 'ip_end' => ip2long($end)];
        }
        return $this->db->delete($this->getBlockedRangeTable(), $where, 1);
    }

    /**
     * List all of the IP ranges blocked in the table
     * @return boolean|array An array will be return containing all blocked IP address ranges if none exist will return false
     */
    public function listBlockedIPRanges()
    {
        $ranges = $this->db->selectAll($this->getBlockedRangeTable());
        if (is_array($ranges)) {
            foreach ($ranges as $i => $range) {
                $ranges[$i]['ip_start'] = long2ip($range['ip_start']);
                $ranges[$i]['ip_end'] = long2ip($range['ip_end']);
            }
        }
        return $ranges;
    }

    /**
     * Returns the ISO county of an IP address
     * @param string $ip This should be the IP address you are checking
     * @return array|false
     */
    public function getIPCountryISO($ip)
    {
        try {
            $search = $this->geoIP->country($ip);
            if (is_object($search)) {
                return $search->country->isoCode;
            }
        } catch (\Exception $e) {
            // Cache any IP that arn't found in the database
        }
        return false;
    }

    /**
     * Add an ISO country to the blocked list
     * @param string $iso This should be the ISO county
     * @return boolean If inserted successfully will return true else will return false
     */
    public function addISOCountryBlock($iso)
    {
        if (!empty(trim($iso)) && is_string($iso) && strlen($iso) === 2) {
            return $this->db->insert($this->getBlockedISOTable(), ['iso' => trim($iso)]);
        }
        return false;
    }

    /**
     * Remove an ISO country from the blocked list
     * @param string $iso This should be the ISO county
     * @return boolean If deleted will return true else will return false
     */
    public function removeISOCountryBlock($iso)
    {
        if (!empty(trim($iso)) && is_string($iso) && strlen($iso) === 2) {
            return $this->db->delete($this->getBlockedISOTable(), ['iso' => trim($iso)]);
        }
        return false;
    }

    /**
     * Gets and return the most likely IP address for the user
     * @return string the users IP will be returned
     */
    public function getUserIP()
    {
        if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
            return $_SERVER["HTTP_CF_CONNECTING_IP"];
        } elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && $_SERVER['HTTP_X_FORWARDED_FOR'] != '') {
            return $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            return $_SERVER['REMOTE_ADDR'];
        }
    }
}
