--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET search_path = public, pg_catalog;

--
-- Name: attempt_sequence; Type: SEQUENCE; Schema: public; Owner: root
--

CREATE SEQUENCE attempt_sequence
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.attempt_sequence OWNER TO root;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: attempt; Type: TABLE; Schema: public; Owner: root; Tablespace: 
--

CREATE TABLE attempt (
    id bigint DEFAULT nextval('attempt_sequence'::regclass) NOT NULL,
    ip character varying(20),
    stamp timestamp with time zone,
    username character varying(100),
    password character varying(100),
    server bigint DEFAULT 1
);


ALTER TABLE public.attempt OWNER TO root;

--
-- Name: ip; Type: TABLE; Schema: public; Owner: root; Tablespace: 
--

CREATE TABLE ip (
    id bigint NOT NULL,
    ip character varying(20)
);


ALTER TABLE public.ip OWNER TO root;

--
-- Name: ipsequence; Type: SEQUENCE; Schema: public; Owner: root
--

CREATE SEQUENCE ipsequence
    START WITH 4
    INCREMENT BY 1
    MINVALUE 4
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.ipsequence OWNER TO root;

--
-- Name: attempt_pkey; Type: CONSTRAINT; Schema: public; Owner: root; Tablespace: 
--

ALTER TABLE ONLY attempt
    ADD CONSTRAINT attempt_pkey PRIMARY KEY (id);


--
-- Name: ip_pkey; Type: CONSTRAINT; Schema: public; Owner: root; Tablespace: 
--

ALTER TABLE ONLY ip
    ADD CONSTRAINT ip_pkey PRIMARY KEY (id);


--
-- Name: attempt_ip; Type: INDEX; Schema: public; Owner: root; Tablespace: 
--

CREATE INDEX attempt_ip ON attempt USING btree (ip);


--
-- Name: attempt_username; Type: INDEX; Schema: public; Owner: root; Tablespace: 
--

CREATE INDEX attempt_username ON attempt USING btree (username);


--
-- Name: public; Type: ACL; Schema: -; Owner: postgres
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM postgres;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO PUBLIC;


--
-- Name: attempt_sequence; Type: ACL; Schema: public; Owner: root
--

REVOKE ALL ON SEQUENCE attempt_sequence FROM PUBLIC;
REVOKE ALL ON SEQUENCE attempt_sequence FROM root;
GRANT ALL ON SEQUENCE attempt_sequence TO root;
GRANT ALL ON SEQUENCE attempt_sequence TO honeypot;


--
-- Name: attempt; Type: ACL; Schema: public; Owner: root
--

REVOKE ALL ON TABLE attempt FROM PUBLIC;
REVOKE ALL ON TABLE attempt FROM root;
GRANT ALL ON TABLE attempt TO root;
GRANT ALL ON TABLE attempt TO honeypot;


--
-- PostgreSQL database dump complete
--

