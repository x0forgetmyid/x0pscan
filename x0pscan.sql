-- proxies definition

CREATE TABLE proxies (ip_addr TEXT, port INT, proxy_type INT, username TEXT, password TEXT, service TEXT, limit_conn INT, dt_added INTEGER, country_code TEXT, "_proxy_id" INTEGER, no_access INTEGER);


-- pscan definition

CREATE TABLE pscan (ip_addr TEXT, port INT, protocol INT, res INT, dt_scan INT, task_id INT, ext_info TEXT);


-- ranges definition

CREATE TABLE ranges (ip_start TEXT, ip_end TEXT, ip_count INT, country_code TEXT, country_name TEXT, region TEXT, city TEXT, dt_added INT, "_ip_start" INTEGER, "_ip_end" INTEGER);

CREATE INDEX ranges__ip_start_IDX ON ranges ("_ip_start","_ip_end");

-- services definition

CREATE TABLE services (
	port INTEGER,
	protocol INTEGER,
	name INTEGER,
	"_task_id" INTEGER
);


-- tasks definition

CREATE TABLE tasks (
	"_ip_start" INTEGER,
	"_ip_end" INTEGER,
	rate INTEGER,
	dt_started INTEGER,
	dt_last INTEGER,
	total_tite INTEGER,
	succesful_scans INTEGER,
	success_all INTEGER,
	total_addrs INTEGER,
	task_id INTEGER
);