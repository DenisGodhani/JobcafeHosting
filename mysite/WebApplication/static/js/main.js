$(function() {
	
	$('.hamburger').on('click', function() {
		$(this).toggleClass('open-nav');
	});

  $('.select_form').each(function() {
      $(this).chosen();

  });

  $('.sm-avatar').closest('.header-area').addClass('profile-header')


     $(function() {
        $('.form-input').focus(function(){
          $(this).parents('.form-group').addClass('focused');
        });

        $('.form-input').blur(function(){
          var inputValue = $(this).val();
          if ( inputValue == "" ) {
            $(this).removeClass('filled');
            $(this).parents('.form-group').removeClass('focused');  
          } else {
            $(this).addClass('filled');
            $(this).parent('.form-group').children('.form-label').addClass('filled-label');
          }
        });  
    }); 

    // Search Form

      $('.search-input input').focus(function() {

        $(this).parent('.search-input').closest('.search-area').addClass('focused');
      });
      
      $('.search-input input').blur(function() {

        $(this).parent('.search-input').closest('.search-area').removeClass('focused');
      });
      

    // Email Validation
    $("#login-email").parent('.input-field').parent(".input-field-area")
        .append('<span class="msg" style="color:#032F3E;"></span>');

    $("#login-email").on("keyup", function(){
      var emailVal= $(this).val();
      var EmailPattern = /^([\w\.\+]{1,})([^\W])(@)([\w]{1,})(\.[\w]{1,})+$/;

      if (!emailVal == "") {
        if (!EmailPattern.test(emailVal)) {

          $(this).parent('.input-field').parent(".input-field-area").find('.msg').text('Please use correct email address format.');
          $(this).parent('.input-field').addClass('erorr-msg');
          $(this).parent('.input-field').removeClass('success-msg');
          $(this).parent('.input-field').parent(".input-field-area").find('.msg').addClass('show');
        }else{
          $(this).parent('.input-field').parent(".input-field-area").find('.msg').empty();
          $(this).parent('.input-field').removeClass('erorr-msg');
          $(this).parent('.input-field').addClass('success-msg');
          $(this).parent('.input-field').parent(".input-field-area").find('.msg').removeClass('show');

        }
      }else{
        $(this).parent('.input-field').parent(".input-field-area").find('.msg').empty();
        $(this).parent('.input-field').parent(".input-field-area").find('.msg').removeClass('show');
      }

    });

    

     $('.form-password .eye').each(function() {

       let fl = true;

        $(this).click(function() {

          let parentE = $(this).closest('.form-password').find('.form-input');
          if (fl == true){
            $(this).addClass('show');
            parentE.addClass('show-password');
            parentE.attr('type', 'text');
            fl = false;
          }else{
            $(this).removeClass('show');
            parentE.removeClass('show-password');
            parentE.attr('type', 'password');
            fl = true;
          }
        });

     });

    // Skill Progress Bar start
    $('svg.radial-progress').each(function( index, value ) { 
        $(this).find($('circle.complete')).removeAttr( 'style' );
    });

    // Activate progress animation on scroll
    $(window).scroll(function(){
      $('svg.radial-progress').each(function( index, value ) { 
        // If svg.radial-progress is approximately 25% vertically into the window when scrolling from the top or the bottom
        if ( 
            $(window).scrollTop() > $(this).offset().top - ($(window).height() * 0.75) &&
            $(window).scrollTop() < $(this).offset().top + $(this).height() - ($(window).height() * 0.25)
        ) {
            // Get percentage of progress
            percent = $(value).data('percentage');
            // Get radius of the svg's circle.complete
            radius = $(this).find($('circle.complete')).attr('r');
            // Get circumference (2πr)
            circumference = 2 * Math.PI * radius;
            // Get stroke-dashoffset value based on the percentage of the circumference
            strokeDashOffset = circumference - ((percent * circumference) / 100);
            // Transition progress for 1.25 seconds
            $(this).find($('circle.complete')).animate({'stroke-dashoffset': strokeDashOffset}, 1250);
        }
      });
    }).trigger('scroll');
    // Skill Progress Bar start

    // Post slideshow init js 

    
    $('.post-slideshow').owlCarousel({
      autoplay: false,
      lazyLoad: true,
      loop: false,
      responsiveClass: true,
      autoHeight: true,
      autoplayTimeout: 7000,
      smartSpeed: 800,
      nav: true,
      dots:true,
      items: 1
  });

    $('.search-field .search-result').each(function(){
        $(this).niceScroll({
          cursorcolor: "#B1B4C1",
          cursorborder: "1px solid #B1B4C1",
          background: "#E2E5EB",
        });
    }); 

    $('.comment-area').each(function(){
        $(this).niceScroll({
          cursorcolor: "#B1B4C1",
          cursorborder: "1px solid #B1B4C1",
          background: "#E2E5EB",
          cursorborderradius: "1px",
          cursoropacitymax: 1,
          cursoropacitymin: 0.2,
          scrollspeed: 100,
        });
    }); 
    $('.chosen-container .chosen-results').each(function(){
        $(this).niceScroll({
          cursorcolor: "#B1B4C1",
          cursorborder: "1px solid #B1B4C1",
          cursorborderradius: "50px",
          background: "#E2E5EB",
          cursoropacitymax: 1,
          cursoropacitymin: 0.2,
          scrollspeed: 300,
        });
    }); 

    $('.post-lg .btn-remove').each(function(){
        $(this).click(function(event) {
          event.preventDefault();
          $(this).closest('.post-lg').fadeOut('fast',function(){
            $(this).empty();
          });
        });

    });
    new WOW().init(); // Wow js init

    // Blog grid init js
    $('.blog-list-area').each(function(index, el) {
      $('.blog-list-area').isotope({
        itemSelector: '.grid-item',
        masonry: {
          columnWidth: '.grid-item'
        }
      });
    });

    // Loading Bar Click
    // $(".btn-load-bar").click(function(event) {
    //     event.preventDefault();
    //     $(this).closest('.ajx-load-form').addClass('active-load-bar');
    //     $(this).closest('.ajx-load-form').append(` <div class="load-bar-overlay">  
    //       <svg id="e8n69p934uw31" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 208.261000 208.290000" shape-rendering="geometricPrecision" text-rendering="geometricPrecision" width="208.261000" height="208.290000"><style><![CDATA[#e8n69p934uw34 {animation: e8n69p934uw34_c_o 1400ms linear infinite normal forwards}@keyframes e8n69p934uw34_c_o { 0% {opacity: 0.500000} 71.428571% {opacity: 0.700000} 85.714286% {opacity: 0.500000} 100% {opacity: 0.500000} }#e8n69p934uw35 {animation: e8n69p934uw35_c_o 1400ms linear infinite normal forwards}@keyframes e8n69p934uw35_c_o { 0% {opacity: 0.500000} 57.142857% {opacity: 1} 71.428571% {opacity: 0.500000} 100% {opacity: 0.500000} }#e8n69p934uw36 {animation: e8n69p934uw36_c_o 1400ms linear infinite normal forwards}@keyframes e8n69p934uw36_c_o { 0% {opacity: 0.500000} 28.571429% {opacity: 1} 42.857143% {opacity: 0.700000} 57.142857% {opacity: 0.500000} 100% {opacity: 0.500000} }#e8n69p934uw37 {animation: e8n69p934uw37_c_o 1400ms linear infinite normal forwards}@keyframes e8n69p934uw37_c_o { 0% {opacity: 0.500000} 42.857143% {opacity: 1} 57.142857% {opacity: 0.700000} 71.428571% {opacity: 0.500000} 100% {opacity: 0.500000} }#e8n69p934uw38 {animation: e8n69p934uw38_c_o 1400ms linear infinite normal forwards}@keyframes e8n69p934uw38_c_o { 0% {opacity: 0.500000} 71.428571% {opacity: 1} 85.714286% {opacity: 0.700000} 100% {opacity: 0.500000} }#e8n69p934uw39 {animation: e8n69p934uw39_c_o 1400ms linear infinite normal forwards}@keyframes e8n69p934uw39_c_o { 0% {opacity: 0.500000} 14.285714% {opacity: 1} 28.571429% {opacity: 0.700000} 42.857143% {opacity: 0.500000} 100% {opacity: 0.500000} }#e8n69p934uw310 {animation: e8n69p934uw310_c_o 1400ms linear infinite normal forwards}@keyframes e8n69p934uw310_c_o { 0% {opacity: 0.500000} 100% {opacity: 1} }#e8n69p934uw311 {animation: e8n69p934uw311_c_o 1400ms linear infinite normal forwards}@keyframes e8n69p934uw311_c_o { 0% {opacity: 0.500000} 85.714286% {opacity: 1} 100% {opacity: 0.700000} }#e8n69p934uw312 {animation: e8n69p934uw312_c_o 1400ms linear infinite normal forwards}@keyframes e8n69p934uw312_c_o { 0% {opacity: 1} 50% {opacity: 0.620000} 100% {opacity: 1} }]]></style><defs><linearGradient id="e8n69p934uw34-fill" x1="0.500000" y1="0" x2="0.500000" y2="1" spreadMethod="pad" gradientUnits="objectBoundingBox"><stop id="e8n69p934uw34-fill-0" offset="0%" stop-color="rgb(3,152,152)"/><stop id="e8n69p934uw34-fill-1" offset="100%" stop-color="rgb(27,199,198)"/></linearGradient><linearGradient id="e8n69p934uw35-fill" x1="0.500000" y1="0" x2="0.500000" y2="1" spreadMethod="pad" gradientUnits="objectBoundingBox"><stop id="e8n69p934uw35-fill-0" offset="0%" stop-color="rgb(3,152,152)"/><stop id="e8n69p934uw35-fill-1" offset="100%" stop-color="rgb(27,199,198)"/></linearGradient><linearGradient id="e8n69p934uw36-fill" x1="0.500000" y1="0" x2="0.500000" y2="1" spreadMethod="pad" gradientUnits="objectBoundingBox"><stop id="e8n69p934uw36-fill-0" offset="0%" stop-color="rgb(3,152,152)"/><stop id="e8n69p934uw36-fill-1" offset="100%" stop-color="rgb(27,199,198)"/></linearGradient><linearGradient id="e8n69p934uw37-fill" x1="0.136000" y1="0.724000" x2="0.005392" y2="0.219000" spreadMethod="pad" gradientUnits="objectBoundingBox"><stop id="e8n69p934uw37-fill-0" offset="0%" stop-color="rgb(3,152,152)"/><stop id="e8n69p934uw37-fill-1" offset="100%" stop-color="rgb(27,199,198)"/></linearGradient><linearGradient id="e8n69p934uw38-fill" x1="0.500000" y1="0" x2="0.500000" y2="1" spreadMethod="pad" gradientUnits="objectBoundingBox"><stop id="e8n69p934uw38-fill-0" offset="0%" stop-color="rgb(3,152,152)"/><stop id="e8n69p934uw38-fill-1" offset="100%" stop-color="rgb(27,199,198)"/></linearGradient><linearGradient id="e8n69p934uw39-fill" x1="0.500000" y1="0" x2="0.500000" y2="1" spreadMethod="pad" gradientUnits="objectBoundingBox"><stop id="e8n69p934uw39-fill-0" offset="0%" stop-color="rgb(3,152,152)"/><stop id="e8n69p934uw39-fill-1" offset="100%" stop-color="rgb(27,199,198)"/></linearGradient><linearGradient id="e8n69p934uw310-fill" x1="0.500000" y1="0" x2="0.500000" y2="1" spreadMethod="pad" gradientUnits="objectBoundingBox"><stop id="e8n69p934uw310-fill-0" offset="0%" stop-color="rgb(3,152,152)"/><stop id="e8n69p934uw310-fill-1" offset="100%" stop-color="rgb(27,199,198)"/></linearGradient><linearGradient id="e8n69p934uw311-fill" x1="0.500000" y1="0" x2="0.500000" y2="1" spreadMethod="pad" gradientUnits="objectBoundingBox"><stop id="e8n69p934uw311-fill-0" offset="0%" stop-color="rgb(3,152,152)"/><stop id="e8n69p934uw311-fill-1" offset="100%" stop-color="rgb(27,199,198)"/></linearGradient></defs><g id="e8n69p934uw32" transform="matrix(1 0 0 1 9553.00123437000002 5305.28999999999996)"><g id="e8n69p934uw33" transform="matrix(1 0 0 1 -9553 -5305.28999999999996)"><path id="e8n69p934uw34" d="M177.507000,530.515000C176.762007,515.776124,170.952551,501.746114,161.060000,490.795000L189.284000,462.580000C206.652460,481.037188,216.667361,505.211526,217.440000,530.544000Z" transform="matrix(1 0 0 1 -9.18000000000003 -429.73400000000004)" opacity="0.5" fill="url(#e8n69p934uw34-fill)" stroke="none" stroke-width="1"/><path id="e8n69p934uw35" d="M155.040000,485.100000C144.094533,475.204782,130.066635,469.394738,115.330000,468.653000L115.330000,428.730000C140.662691,429.501627,164.837374,439.516670,183.294000,456.886000Z" transform="matrix(1 0 0 1 -7.85000000000000 -428.71100000000001)" opacity="0.5" fill="url(#e8n69p934uw35-fill)" stroke="none" stroke-width="1"/><path id="e8n69p934uw36" d="M32.826000,462.550000L61.031000,490.774000C51.134813,501.723709,45.321764,515.753868,44.574000,530.494000L4.660000,530.494000C5.434775,505.165990,15.453730,480.997564,32.826000,462.550000Z" transform="matrix(1 0 0 1 -4.66123437000000 -429.69400000000002)" opacity="0.5" fill="url(#e8n69p934uw36-fill)" stroke="none" stroke-width="1"/><path id="e8n69p934uw37" d="M106.435000,468.644000C91.696142,469.389074,77.666159,475.198519,66.715000,485.091000L38.510000,456.866000C56.963712,439.492163,81.140182,429.476380,106.474000,428.710000Z" transform="matrix(1 0 0 1 -5.61500000000000 -428.70999999999998)" opacity="0.5" fill="url(#e8n69p934uw37-fill)" stroke="none" stroke-width="1"/><path id="e8n69p934uw38" d="M161.060000,579.120000C170.952551,568.168886,176.762007,554.138876,177.507000,539.400000L217.421000,539.400000C216.639448,564.730558,206.625804,588.901864,189.265000,607.364000Z" transform="matrix(1 0 0 1 -9.18000000000000 -431.99199999999996)" opacity="0.5" fill="url(#e8n69p934uw38-fill)" stroke="none" stroke-width="1"/><path id="e8n69p934uw39" d="M44.573000,539.379000C45.310559,554.118155,51.117424,568.149939,61.011000,579.100000L32.786000,607.300000C15.419151,588.843375,5.404435,564.670904,4.630000,539.340000Z" transform="matrix(1 0 0 1 -4.64123437000000 -431.92800000000000)" opacity="0.5" fill="url(#e8n69p934uw39-fill)" stroke="none" stroke-width="1"/><path id="e8n69p934uw310" d="M66.694000,585.130000C77.636959,595.043638,91.667836,600.873940,106.414000,601.635000L106.414000,641.550000C81.081967,640.774421,56.908519,630.759535,38.450000,613.393000Z" transform="matrix(1 0 0 1 -5.55500000000000 -433.23900000000003)" opacity="0.5" fill="url(#e8n69p934uw310-fill)" stroke="none" stroke-width="1"/><path id="e8n69p934uw311" d="M115.300000,601.588000C130.042696,600.855124,144.078733,595.048169,155.030000,585.151000L183.235000,613.375000C164.780828,630.748125,140.604640,640.763791,115.271000,641.531000Z" transform="matrix(1 0 0 1 -7.84800000000000 -433.25999999999999)" opacity="0.5" fill="url(#e8n69p934uw311-fill)" stroke="none" stroke-width="1"/></g><text id="e8n69p934uw312" dx="0" dy="0" font-family="Lato-Bold, Lato" font-size="20" font-weight="bold" transform="matrix(1 0 0 1 -9492.95312500000000 -5186.98437500000000)" fill="rgb(11,167,167)" stroke="none" stroke-width="1"><![CDATA[Loading ...]]></text></g></svg></div>
    //     `);
    // });

  $(".code-send").click(function() {
    $(this).addClass('active');
  });

  $(".basket").click(function() {
    $(this).closest('.add-basket-area').find('.bottom-area').toggle(200)
  });

  $("#remove_shopping").on("click", function(){
    $(this).closest('.add-basket-area').addClass('remove-msg');
  });

  $("#close_shopping").on("click", function(){
    $(this).closest('.add-basket-area').removeClass('remove-msg');
  });
  
});