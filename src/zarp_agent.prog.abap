REPORT zarp_agent.

CLASS lcl_agent DEFINITION
  FINAL
  CREATE PRIVATE.

  PUBLIC SECTION.
    CLASS-METHODS run.

  PRIVATE SECTION.
    CONSTANTS lc_virt_host TYPE icfname VALUE 'DEFAULT_HOST'.
    CONSTANTS lc_protocol_http TYPE char10 VALUE 'HTTP'.
    CONSTANTS lc_service_name TYPE icfname VALUE 'ZARP'.
    CONSTANTS lc_service_url TYPE string VALUE '/sap/bc/zarp'.
    CONSTANTS lc_server_port_prefix TYPE char32 VALUE 'icm/server_port_'.

    CLASS-METHODS is_service_installed
      RETURNING
        VALUE(rv_installed) TYPE abap_bool.

    CLASS-METHODS get_test_url
      RETURNING
        VALUE(rv_url) TYPE string.

    CLASS-METHODS open_in_browser
      IMPORTING
        iv_url TYPE string.
ENDCLASS.


CLASS lcl_agent IMPLEMENTATION.

  METHOD is_service_installed.
    DATA lv_hostnumber TYPE icfhostnum.
    DATA lv_urlsuffix TYPE icfredurl.
    DATA lv_icf_name TYPE icfname.

    SELECT SINGLE hostnumber
      FROM icfvirhost
      WHERE icf_name EQ @lc_virt_host
        AND protocol EQ @lc_protocol_http
      INTO @lv_hostnumber.
    CHECK sy-subrc EQ 0.

    CALL METHOD cl_icf_tree=>if_icf_tree~service_from_url
      EXPORTING
        url                   = lc_service_url
        hostnumber            = lv_hostnumber
        authority_check       = space
      IMPORTING
        urlsuffix             = lv_urlsuffix
        icf_name              = lv_icf_name
      EXCEPTIONS
        wrong_application     = 1
        no_application        = 2
        not_allow_application = 3
        wrong_url             = 4
        no_authority          = 5
        OTHERS                = 6.
    CHECK sy-subrc EQ 0.
    CHECK lv_icf_name EQ lc_service_name.
    CHECK lv_urlsuffix EQ space.

    rv_installed = abap_true.
  ENDMETHOD.

  METHOD get_test_url.
    DATA lv_param_value TYPE string.
    DATA lv_opt_name TYPE string.
    DATA lv_opt_value TYPE string.
    DATA lv_protocol TYPE string.
    DATA lv_entry_port TYPE string.
    DATA lv_http_port TYPE string.
    DATA lv_https_port TYPE string.
    DATA lv_host TYPE string.
    DATA lv_index TYPE i.

    WHILE lv_index LT 30.
      lv_param_value = space.

      cl_spfl_profile_parameter=>get_value(
        EXPORTING
          name                = |{ lc_server_port_prefix }{ lv_index }|
        IMPORTING
          value               = lv_param_value ).

      IF lv_param_value NE space.
        TRANSLATE lv_param_value TO UPPER CASE.

        CLEAR: lv_protocol, lv_entry_port.

        SPLIT lv_param_value AT ',' INTO TABLE DATA(lt_options).

        LOOP AT lt_options ASSIGNING FIELD-SYMBOL(<lv_option>).
          CONDENSE <lv_option>.
          SPLIT <lv_option> AT '=' INTO lv_opt_name lv_opt_value.

          IF lv_opt_name EQ 'PROT'.
            lv_protocol = lv_opt_value.
          ELSEIF lv_opt_name EQ 'PORT'.
            lv_entry_port = lv_opt_value.
          ENDIF.
        ENDLOOP.

        IF lv_protocol EQ 'HTTP' AND lv_http_port EQ space.
          lv_http_port = lv_entry_port.
        ELSEIF lv_protocol EQ 'HTTPS' AND lv_https_port EQ space.
          lv_https_port = lv_entry_port.
        ENDIF.
      ENDIF.

      IF lv_http_port NE space
         AND lv_https_port NE space.
        EXIT.
      ENDIF.

      lv_index = lv_index + 1.
    ENDWHILE.

    IF lv_http_port EQ space.
      CALL METHOD cl_spfl_profile_parameter=>get_value
        EXPORTING
          name  = 'icm/HTTP/port'
        IMPORTING
          value = lv_http_port.
      CONDENSE lv_http_port.
    ENDIF.

    CALL METHOD cl_spfl_profile_parameter=>get_value
      EXPORTING
        name  = 'SAPLOCALHOSTFULL'
      IMPORTING
        value = lv_host.
    CONDENSE lv_host.

    IF lv_host EQ space.
      lv_host = sy-host.
    ENDIF.

    lv_host = to_lower( lv_host ).

    IF lv_https_port NE space.
      rv_url = |https://{ lv_host }:{ lv_https_port }{ lc_service_url }|.
    ELSEIF lv_http_port NE space.
      rv_url = |http://{ lv_host }:{ lv_http_port }{ lc_service_url }|.
    ENDIF.
  ENDMETHOD.

  METHOD open_in_browser.
    CALL METHOD cl_gui_frontend_services=>execute
      EXPORTING
        document = iv_url
      EXCEPTIONS
        OTHERS   = 1.
    IF sy-subrc NE 0.
      MESSAGE |Browser could not be started. Open the test URL manually: { iv_url }|
         TYPE rs_c_success DISPLAY LIKE rs_c_error.
    ELSE.
      MESSAGE |Service ZARP found. Opening test URL in the browser: { iv_url }|
         TYPE rs_c_success.
    ENDIF.
  ENDMETHOD.

  METHOD run.
    IF is_service_installed( ) NE abap_true.
      MESSAGE 'ICF service ZARP is not installed at /default_host/sap/bc/zarp. Install the ARP Bridge Agent service in SICF'
        TYPE rs_c_success DISPLAY LIKE rs_c_error.
      RETURN.
    ENDIF.

    DATA(lv_url) = get_test_url( ).

    IF lv_url EQ space.
      MESSAGE 'Unable to determine ICM HTTP port (profile parameters icm/server_port_N and icm/HTTP/port)'
        TYPE rs_c_success DISPLAY LIKE rs_c_error.
      RETURN.
    ENDIF.

    open_in_browser( lv_url ).
  ENDMETHOD.
ENDCLASS.


START-OF-SELECTION.
  lcl_agent=>run( ).
