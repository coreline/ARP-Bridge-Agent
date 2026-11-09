CLASS zcl_arp_agent DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    INTERFACES if_http_extension.

  PRIVATE SECTION.
    CONSTANTS gc_relay_host TYPE string VALUE 'arp.abap4.ru'.
ENDCLASS.



CLASS ZCL_ARP_AGENT IMPLEMENTATION.


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Instance Public Method ZCL_ARP_AGENT->IF_HTTP_EXTENSION~HANDLE_REQUEST
* +-------------------------------------------------------------------------------------------------+
* | [--->] SERVER                         TYPE REF TO IF_HTTP_SERVER
* +--------------------------------------------------------------------------------------</SIGNATURE>
  METHOD if_http_extension~handle_request.
    DATA: lv_action   TYPE string,
          lv_json     TYPE string,
          lv_arp_id   TYPE string,
          lv_identity TYPE string,
          lv_hash     TYPE string,
          lv_html     TYPE string.

    lv_action = server->request->get_form_field( name = 'action' ).

    IF lv_action = 'health'.
      lv_json = '{"status":"ok","agent":"ARP"}'.
      server->response->set_status( code = 200 reason = 'OK' ).
      server->response->set_content_type( content_type = 'application/json; charset=utf-8' ).
      server->response->set_cdata( data = lv_json ).
      RETURN.
    ENDIF.

    lv_arp_id = server->request->get_form_field( name = 'arpId' ).

    IF lv_arp_id IS INITIAL.
      lv_identity = |{ sy-host }-{ sy-sysid }-{ sy-mandt }-{ sy-uname }|.
      TRY.
          CALL METHOD cl_abap_message_digest=>calculate_hash_for_char
            EXPORTING
              if_algorithm  = 'MD5'
              if_data       = lv_identity
            IMPORTING
              ef_hashstring = lv_hash.
        CATCH cx_abap_message_digest.
          server->response->set_status( code = 500 reason = 'ARP-ID generation failed' ).
          server->response->set_content_type( content_type = 'text/plain; charset=utf-8' ).
          server->response->set_cdata( data = 'Unable to calculate hash for ARP-ID' ).
          RETURN.
      ENDTRY.
      lv_arp_id = lv_hash(32).
    ELSE.
      TRANSLATE lv_arp_id TO LOWER CASE.
      IF strlen( lv_arp_id ) <> 32 OR lv_arp_id CN '0123456789abcdef'.
        server->response->set_status( code = 400 reason = 'Invalid ARP-ID' ).
        server->response->set_content_type( content_type = 'text/plain; charset=utf-8' ).
        server->response->set_cdata( data = 'ARP-ID must contain exactly 32 hexadecimal characters' ).
        RETURN.
      ENDIF.
    ENDIF.

    TRANSLATE lv_arp_id TO LOWER CASE.

    DATA(lv_endl) = cl_abap_char_utilities=>newline.

    lv_html = '<!doctype html>' && lv_endl
           && '<html lang="ru">' && lv_endl
           && '<head>' && lv_endl
           && '  <meta charset="utf-8">' && lv_endl
           && '  <meta name="viewport" content="width=device-width, initial-scale=1">' && lv_endl
           && '  <title>ARP Bridge Agent</title>' && lv_endl
           && '  <link rel="stylesheet" crossorigin="anonymous" href="https://' &&
              gc_relay_host && '/arp-agent.css">' && lv_endl
           && '  <script>window.ARP_ID = "' && lv_arp_id && '";</script>' && lv_endl
           && '  <script defer crossorigin="anonymous" src="https://' &&
              gc_relay_host && '/arp-agent.js"></script>' && lv_endl
           && '</head>' && lv_endl
           && '<body></body>' && lv_endl
           && '</html>' && lv_endl.

    server->response->set_status( code = 200 reason = 'OK' ).
    server->response->set_content_type( content_type = 'text/html; charset=utf-8' ).
    server->response->set_header_field( name = 'Cache-Control' value = 'no-store' ).
    server->response->set_cdata( data = lv_html ).
  ENDMETHOD.
ENDCLASS.