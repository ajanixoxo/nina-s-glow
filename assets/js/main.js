(function ($) {

    ('use strict');

    /*----------------------------------------
    - Resize Event
----------------------------------------*/

    window.addEventListener('resize', function () { });
    
	/*---------------------------------------
		Yena's Preloader
---------------------------------*/
    $(window).on('load', function () {
        var wind = $(window);
        $('.loading').delay(500).fadeOut('slow');
    });
    /*------------------------------------
	    WOW
	    ------------------------------------- */
    new WOW().init();
    /*----------------------------------------*/
    /* Newsletter Popup
/*----------------------------------------*/
    setTimeout(function () {
        $('.popup_wrapper').css({
            opacity: '1',
            visibility: 'visible',
        });
        $('.popup_off').on('click', function () {
            $('.popup_wrapper').fadeOut(500);
        });
    }, 5000);
    /*------------------------------------
	    Autoplay Video Slider
	    ------------------------------------- */
    var slideWrapper = $('.autoplay-video_slider'),
        iframes = slideWrapper.find('.embed-player'),
        lazyImages = slideWrapper.find('.slide-image'),
        lazyCounter = 0;

    // POST commands to YouTube or Vimeo API
    function postMessageToPlayer(player, command) {
        if (player == null || command == null) return;
        player.contentWindow.postMessage(JSON.stringify(command), '*');
    }

    // When the slide is changing
    function playPauseVideo(slick, control) {
        var currentSlide, slideType, startTime, player, video;

        currentSlide = slick.find('.slick-current');
        slideType = currentSlide.attr('class').split(' ')[1];
        player = currentSlide.find('iframe').get(0);
        startTime = currentSlide.data('video-start');

        if (slideType === 'vimeo') {
            switch (control) {
                case 'play':
                    if (
                        startTime != null &&
                        startTime > 0 &&
                        !currentSlide.hasClass('started')
                    ) {
                        currentSlide.addClass('started');
                        postMessageToPlayer(player, {
                            method: 'setCurrentTime',
                            value: startTime,
                        });
                    }
                    postMessageToPlayer(player, {
                        method: 'play',
                        value: 1,
                    });
                    break;
                case 'pause':
                    postMessageToPlayer(player, {
                        method: 'pause',
                        value: 1,
                    });
                    break;
            }
        } else if (slideType === 'youtube') {
            switch (control) {
                case 'play':
                    postMessageToPlayer(player, {
                        event: 'command',
                        func: 'mute',
                    });
                    postMessageToPlayer(player, {
                        event: 'command',
                        func: 'playVideo',
                    });
                    break;
                case 'pause':
                    postMessageToPlayer(player, {
                        event: 'command',
                        func: 'pauseVideo',
                    });
                    break;
            }
        } else if (slideType === 'video') {
            video = currentSlide.children('video').get(0);
            if (video != null) {
                if (control === 'play') {
                    video.play();
                } else {
                    video.pause();
                }
            }
        }
    }

    // Resize player
    function resizePlayer(iframes, ratio) {
        if (!iframes[0]) return;
        var win = $('.autoplay-video_slider'),
            width = win.width(),
            playerWidth,
            height = win.height(),
            playerHeight,
            ratio = ratio || 16 / 9;

        iframes.each(function () {
            var current = $(this);
            if (width / ratio < height) {
                playerWidth = Math.ceil(height * ratio);
                current
                    .width(playerWidth)
                    .height(height)
                    .css({
                        left: (width - playerWidth) / 2,
                        top: 0,
                    });
            } else {
                playerHeight = Math.ceil(width / ratio);
                current
                    .width(width)
                    .height(playerHeight)
                    .css({
                        left: 0,
                        top: (height - playerHeight) / 2,
                    });
            }
        });
    }

    // DOM Ready
    $(function () {
        // Initialize
        slideWrapper.on('init', function (slick) {
            slick = $(slick.currentTarget);
            setTimeout(function () {
                playPauseVideo(slick, 'play');
            }, 1000);
            resizePlayer(iframes, 16 / 9);
        });
        slideWrapper.on('beforeChange', function (event, slick) {
            slick = $(slick.$slider);
            playPauseVideo(slick, 'pause');
        });
        slideWrapper.on('afterChange', function (event, slick) {
            slick = $(slick.$slider);
            playPauseVideo(slick, 'play');
        });
        slideWrapper.on(
            'lazyLoaded',
            function (event, slick, image, imageSource) {
                lazyCounter++;
                if (lazyCounter === lazyImages.length) {
                    lazyImages.addClass('show');
                    // slideWrapper.slick("slickPlay");
                }
            }
        );

        //start the slider
        slideWrapper.slick({
            fade: true,
            autoplay: true,
            draggable: true,
            swipeToSlide: true,
            swipe: false,
            autoplaySpeed: 10000,
            lazyLoad: 'progressive',
            pauseOnHover: false,
            pauseOnFocus: false,
            speed: 20,
            arrows: false,
            dots: false,
            cssEase: 'cubic-bezier(0.87, 0.03, 0.41, 0.9)',
        });
    });

    // Resize event
    $(window).on('resize.slickVideoPlayer', function () {
        resizePlayer(iframes, 16 / 9);
    });
    /*---------------------------------------
		Sticky Menu Activation
---------------------------------*/
    $(window).on('scroll', function () {
        if ($(this).scrollTop() > 300) {
            $('.header-sticky').addClass('sticky');
        } else {
            $('.header-sticky').removeClass('sticky');
        }
    });
    /*----------------------------------------*/
    /*  Toolbar Button
/*----------------------------------------*/
    var $overlay = $('.global-overlay');
    $('.toolbar-btn').on('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        var $this = $(this);
        var target = $this.attr('href');
        var prevTarget = $this
            .parent()
            .siblings()
            .children('.toolbar-btn')
            .attr('href');
        $(target).toggleClass('open');
        $(prevTarget).removeClass('open');
        $($overlay).addClass('overlay-open');
    });

    /*----------------------------------------*/
    /*  Click on Documnet
/*----------------------------------------*/
    var $body = $('.global-overlay');

    $body.on('click', function (e) {
        var $target = e.target;
        var dom = $('.main-wrapper').children();

        if (
            !$($target).is('.toolbar-btn') &&
            !$($target).parents().is('.open')
        ) {
            dom.removeClass('open');
            dom.find('.open').removeClass('open');
            $overlay.removeClass('overlay-open');
        }
    });

    /*----------------------------------------*/
    /*  Close Button Actions
/*----------------------------------------*/
    $('.btn-close, .btn-close-2').on('click', function (e) {
        var dom = $('.main-wrapper').children();
        e.preventDefault();
        var $this = $(this);
        $this.parents('.open').removeClass('open');
        dom.find('.global-overlay').removeClass('overlay-open');
    });
    /*----------------------------------------*/
    /*  Offcanvas
/*----------------------------------------*/
    /*Variables*/
    var $offcanvasNav = $(
            '.offcanvas-menu, .offcanvas-minicart_menu, .offcanvas-search_menu, .mobile-menu'
        ),
        $offcanvasNavWrap = $(
            '.offcanvas-menu_wrapper, .offcanvas-minicart_wrapper, .offcanvas-search_wrapper, .mobile-menu_wrapper'
        ),
        $offcanvasNavSubMenu = $offcanvasNav.find('.sub-menu'),
        $menuToggle = $('.menu-btn'),
        $menuClose = $('.btn-close');

    /*Close Off Canvas Sub Menu*/
    $offcanvasNavSubMenu.slideUp();

    /*Category Sub Menu Toggle*/
    $offcanvasNav.on('click', 'li a, li .menu-expand', function (e) {
        var $this = $(this);
        if (
            $this
                .parent()
                .attr('class')
                .match(
                    /\b(menu-item-has-children|has-children|has-sub-menu)\b/
                ) &&
            ($this.attr('href') === '#' ||
                $this.attr('href') === '' ||
                $this.hasClass('menu-expand'))
        ) {
            e.preventDefault();
            if ($this.siblings('ul:visible').length) {
                $this.siblings('ul').slideUp('slow');
            } else {
                $this
                    .closest('li')
                    .siblings('li')
                    .find('ul:visible')
                    .slideUp('slow');
                $this.closest('li').siblings('li').removeClass('menu-open');
                $this.siblings('ul').slideDown('slow');
                $this.parent().siblings().children('ul').slideUp();
            }
        }
        if (
            $this.is('a') ||
            $this.is('span') ||
            $this.attr('class').match(/\b(menu-expand)\b/)
        ) {
            $this.parent().toggleClass('menu-open');
        } else if (
            $this.is('li') &&
            $this.attr('class').match(/\b('menu-item-has-children')\b/)
        ) {
            $this.toggleClass('menu-open');
        }
    });

    $('.btn-close').on('click', function (e) {
        e.preventDefault();
        $('.mobile-menu .sub-menu').slideUp();
        $('.mobile-menu .menu-item-has-children').removeClass('menu-open');
    });
    /*----------------------------------------*/
    /*  Nice Select
/*----------------------------------------*/
    $(document).ready(function () {
        $('.nice-select').niceSelect();
    });

    /*--------------------------------
    Ajax Contact Form
-------------------------------- */
    $(function () {
        // Get the form.
        var form = $('#contact-form');
        // Get the messages div.
        var formMessages = $('.form-messege');
        // Set up an event listener for the contact form.
        $(form).submit(function (e) {
            // Stop the browser from submitting the form.
            e.preventDefault();
            // Serialize the form data.
            var formData = $(form).serialize();
            // Submit the form using AJAX.
            $.ajax({
                type: 'POST',
                url: $(form).attr('action'),
                data: formData,
            })
                .done(function (response) {
                    // Make sure that the formMessages div has the 'success' class.
                    $(formMessages).removeClass('error');
                    $(formMessages).addClass('success');

                    // Set the message text.
                    $(formMessages).text(response);

                    // Clear the form.
                    $('#contact-form input,#contact-form textarea').val('');
                })
                .fail(function (data) {
                    // Make sure that the formMessages div has the 'error' class.
                    $(formMessages).removeClass('success');
                    $(formMessages).addClass('error');

                    // Set the message text.
                    if (data.responseText !== '') {
                        $(formMessages).text(data.responseText);
                    } else {
                        $(formMessages).text(
                            'Oops! An error occured and your message could not be sent.'
                        );
                    }
                });
        });
    });
    /*----------------------------------------*/
    /* Yena's Countdown
	/*----------------------------------------*/
    // Check if element exists
    $.fn.elExists = function () {
        return this.length > 0;
    };

    function makeTimer($endDate, $this, $format) {
        var today = new Date();

        var BigDay = new Date($endDate),
            msPerDay = 24 * 60 * 60 * 1000,
            timeLeft = BigDay.getTime() - today.getTime(),
            e_daysLeft = timeLeft / msPerDay,
            daysLeft = Math.floor(e_daysLeft),
            e_hrsLeft = (e_daysLeft - daysLeft) * 24,
            hrsLeft = Math.floor(e_hrsLeft),
            e_minsLeft = (e_hrsLeft - hrsLeft) * 60,
            minsLeft = Math.floor((e_hrsLeft - hrsLeft) * 60),
            e_secsLeft = (e_minsLeft - minsLeft) * 60,
            secsLeft = Math.floor((e_minsLeft - minsLeft) * 60);

        var yearsLeft = 0;
        var monthsLeft = 0;
        var weeksLeft = 0;

        if ($format != 'short') {
            if (daysLeft > 365) {
                yearsLeft = Math.floor(daysLeft / 365);
                daysLeft = daysLeft % 365;
            }

            if (daysLeft > 30) {
                monthsLeft = Math.floor(daysLeft / 30);
                daysLeft = daysLeft % 30;
            }
            if (daysLeft > 7) {
                weeksLeft = Math.floor(daysLeft / 7);
                daysLeft = daysLeft % 7;
            }
        }

        var yearsLeft = yearsLeft < 10 ? '0' + yearsLeft : yearsLeft,
            monthsLeft = monthsLeft < 10 ? '0' + monthsLeft : monthsLeft,
            weeksLeft = weeksLeft < 10 ? '0' + weeksLeft : weeksLeft,
            daysLeft = daysLeft < 10 ? '0' + daysLeft : daysLeft,
            hrsLeft = hrsLeft < 10 ? '0' + hrsLeft : hrsLeft,
            minsLeft = minsLeft < 10 ? '0' + minsLeft : minsLeft,
            secsLeft = secsLeft < 10 ? '0' + secsLeft : secsLeft,
            yearsText = yearsLeft > 1 ? 'years' : 'year',
            monthsText = monthsLeft > 1 ? 'months' : 'month',
            weeksText = weeksLeft > 1 ? 'weeks' : 'week',
            daysText = daysLeft > 1 ? 'days' : 'day',
            hourText = hrsLeft > 1 ? 'hrs' : 'hr',
            minsText = minsLeft > 1 ? 'mins' : 'min',
            secText = secsLeft > 1 ? 'secs' : 'sec';

        var $markup = {
            wrapper: $this.find('.countdown__item'),
            year: $this.find('.yearsLeft'),
            month: $this.find('.monthsLeft'),
            week: $this.find('.weeksLeft'),
            day: $this.find('.daysLeft'),
            hour: $this.find('.hoursLeft'),
            minute: $this.find('.minsLeft'),
            second: $this.find('.secsLeft'),
            yearTxt: $this.find('.yearsText'),
            monthTxt: $this.find('.monthsText'),
            weekTxt: $this.find('.weeksText'),
            dayTxt: $this.find('.daysText'),
            hourTxt: $this.find('.hoursText'),
            minTxt: $this.find('.minsText'),
            secTxt: $this.find('.secsText'),
        };

        var elNumber = $markup.wrapper.length;
        $this.addClass('item-' + elNumber);
        $($markup.year).html(yearsLeft);
        $($markup.yearTxt).html(yearsText);
        $($markup.month).html(monthsLeft);
        $($markup.monthTxt).html(monthsText);
        $($markup.week).html(weeksLeft);
        $($markup.weekTxt).html(weeksText);
        $($markup.day).html(daysLeft);
        $($markup.dayTxt).html(daysText);
        $($markup.hour).html(hrsLeft);
        $($markup.hourTxt).html(hourText);
        $($markup.minute).html(minsLeft);
        $($markup.minTxt).html(minsText);
        $($markup.second).html(secsLeft);
        $($markup.secTxt).html(secText);
    }

    if ($('.countdown').elExists) {
        $('.countdown').each(function () {
            var $this = $(this);
            var $endDate = $(this).data('countdown');
            var $format = $(this).data('format');
            setInterval(function () {
                makeTimer($endDate, $this, $format);
            }, 0);
        });
    }

    /*----------------------------------------*/
    /*  Cart Plus Minus Button
	/*----------------------------------------*/
    $('.cart-plus-minus').append(
        '<div class="dec qtybutton"><i class="zmdi zmdi-chevron-down"></i></div><div class="inc qtybutton"><i class="zmdi zmdi-chevron-up"></i></div>'
    );
    $('.qtybutton').on('click', function () {
        var $button = $(this);
        var oldValue = $button.parent().find('input').val();
        if ($button.hasClass('inc')) {
            var newVal = parseFloat(oldValue) + 1;
        } else {
            // Don't allow decrementing below zero
            if (oldValue > 1) {
                var newVal = parseFloat(oldValue) - 1;
            } else {
                newVal = 1;
            }
        }
        $button.parent().find('input').val(newVal);
    });

    /*----------------------------------------*/
    /* Toggle Function Active
	/*----------------------------------------*/
    // showlogin toggle
    $('#showlogin').on('click', function () {
        $('#checkout-login').slideToggle(900);
    });
    // showlogin toggle
    $('#showcoupon').on('click', function () {
        $('#checkout_coupon').slideToggle(900);
    });
    // showlogin toggle
    $('#cbox').on('click', function () {
        $('#cbox-info').slideToggle(900);
    });

    // showlogin toggle
    $('#ship-box').on('click', function () {
        $('#ship-box-info').slideToggle(1000);
    });

    /*---------------------------------------------*/
    /*  Yena's CounterUp
	/*----------------------------------------------*/
    $('.count').counterUp({
        delay: 10,
        time: 1000,
    });

    /*----------------------------------------*/
    /*  Yena's Product View Mode
	/*----------------------------------------*/
    function porductViewMode() {
        $(window).on({
            load: function () {
                var activeChild = $('.product-view-mode a.active');
                var firstChild = $('.product-view-mode').children().first();
                var window_width = $(window).width();

                if (window_width < 768) {
                    $('.product-view-mode a').removeClass('active');
                    $('.product-view-mode')
                        .children()
                        .first()
                        .addClass('active');
                    $('.shop-product-wrap')
                        .removeClass('gridview-3 gridview-4 gridview-5')
                        .addClass('gridview-2');
                }
            },
            resize: function () {
                var ww = $(window).width();
                var activeChild = $('.product-view-mode a.active');
                var firstChild = $('.product-view-mode').children().first();
                var defaultView = $('.product-view-mode').data('default');

                if (ww < 1200 && ww > 575) {
                    if (activeChild.hasClass('grid-5')) {
                        $('.product-view-mode a.grid-5').removeClass('active');
                        if (defaultView == 4) {
                            $('.product-view-mode a.grid-4').addClass('active');
                            $('.shop-product-wrap')
                                .removeClass('gridview-2 gridview-3 gridview-5')
                                .addClass('gridview-4');
                        } else if (defaultView == 'list') {
                            $('.product-view-mode a.list').addClass('active');
                            $('.shop-product-wrap')
                                .removeClass(
                                    'gridview-2 gridview-3 gridview-4 gridview-5'
                                )
                                .addClass('listview');
                        } else {
                            $('.product-view-mode a.grid-3').addClass('active');
                            $('.shop-product-wrap')
                                .removeClass('gridview-2 gridview-4 gridview-5')
                                .addClass('gridview-3');
                        }
                    }
                }

                if (ww < 768 && ww > 575) {
                    if (activeChild.hasClass('grid-4')) {
                        $('.product-view-mode a.grid-4').removeClass('active');
                        if (defaultView == 'list') {
                            $('.product-view-mode a.list').addClass('active');
                            $('.shop-product-wrap')
                                .removeClass(
                                    'gridview-2 gridview-3 gridview-4 gridview-5'
                                )
                                .addClass('listview');
                        } else {
                            $('.product-view-mode a.grid-3').addClass('active');
                            $('.shop-product-wrap')
                                .removeClass('gridview-2 gridview-4 gridview-5')
                                .addClass('gridview-3');
                        }
                    }
                }
                if (activeChild.hasClass('list')) {
                } else {
                    if (ww < 576) {
                        $('.product-view-mode a').removeClass('active');
                        $('.product-view-mode')
                            .children()
                            .first()
                            .addClass('active');
                        $('.shop-product-wrap')
                            .removeClass('gridview-3 gridview-4 gridview-5')
                            .addClass('gridview-2');
                    } else {
                        if (activeChild.hasClass('grid-2')) {
                            if (ww < 1200) {
                                $(
                                    '.product-view-mode a:not(:first-child)'
                                ).removeClass('active');
                            } else {
                                $('.product-view-mode a').removeClass('active');
                                $('.product-view-mode a:nth-child(2)').addClass(
                                    'active'
                                );
                                $('.shop-product-wrap')
                                    .removeClass(
                                        'gridview-2 gridview-4 gridview-5'
                                    )
                                    .addClass('gridview-3');
                            }
                        }
                    }
                }
            },
        });
        $('.product-view-mode a').on('click', function (e) {
            e.preventDefault();

            var shopProductWrap = $('.shop-product-wrap');
            var viewMode = $(this).data('target');

            $('.product-view-mode a').removeClass('active');
            $(this).addClass('active');
            if (viewMode == 'listview') {
                shopProductWrap.removeClass('grid');
            } else {
                if (shopProductWrap.not('.grid'))
                    shopProductWrap.addClass('grid');
            }
            shopProductWrap
                .removeClass(
                    'gridview-2 gridview-3 gridview-4 gridview-5 listview'
                )
                .addClass(viewMode);
        });
    }
    porductViewMode();

    /*----------------------------------------*/
    /*  Star Rating Js
	/*----------------------------------------*/
    $(function () {
        $('.star-rating').barrating({
            theme: 'fontawesome-stars',
        });
    });

    /*-------------------------------------------------*/
    /* Sticky Sidebar
	/*-------------------------------------------------*/
    $('#sticky-sidebar').theiaStickySidebar({
        // Settings
        additionalMarginTop: 80,
    });

    /*-------------------------------------------------*/
    /* Bootstraps 4 Tooltip
	/*-------------------------------------------------*/
    $(function () {
        $('[data-bs-toggle="tooltip"]').tooltip();
    });
    /*--------------------------------
	Price Slider Active
	-------------------------------- */
    var sliderrange = $('#slider-range');
    var amountprice = $('#amount');
    $(function () {
        sliderrange.slider({
            range: true,
            min: 80,
            max: 1900,
            values: [0, 2000],
            slide: function (event, ui) {
                amountprice.val('$' + ui.values[0] + ' - $' + ui.values[1]);
            },
        });
        amountprice.val(
            '$' +
                sliderrange.slider('values', 0) +
                ' - $' +
                sliderrange.slider('values', 1)
        );
    });
    /*----------------------------------------*/
    /*  Slick Carousel
	/*----------------------------------------*/
    var $html = $('html');
    var $body = $('body');
    var $elementCarousel = $('.yena-element-carousel');
    // Check if element exists
    $.fn.elExists = function () {
        return this.length > 0;
    };

    /*For RTL*/
    if ($html.attr('dir') == 'rtl' || $body.attr('dir') == 'rtl') {
        $elementCarousel.attr('dir', 'rtl');
    }

    if ($elementCarousel.elExists()) {
        var slickInstances = [];

        /*For RTL*/
        if ($html.attr('dir') == 'rtl' || $body.attr('dir') == 'rtl') {
            $elementCarousel.attr('dir', 'rtl');
        }

        $elementCarousel.each(function (index, element) {
            var $this = $(this);

            // Carousel Options

            var $options =
                typeof $this.data('slick-options') !== 'undefined'
                    ? $this.data('slick-options')
                    : '';

            var $spaceBetween = $options.spaceBetween
                    ? parseInt($options.spaceBetween, 10)
                    : 0,
                $spaceBetween_xl = $options.spaceBetween_xl
                    ? parseInt($options.spaceBetween_xl, 10)
                    : 0,
                $rowSpace = $options.rowSpace
                    ? parseInt($options.rowSpace, 10)
                    : 0,
                $rows = $options.rows ? $options.rows : false,
                $vertical = $options.vertical ? $options.vertical : false,
                $focusOnSelect = $options.focusOnSelect
                    ? $options.focusOnSelect
                    : false,
                $pauseOnHover = $options.pauseOnHover
                    ? $options.pauseOnHover
                    : false,
                $pauseOnFocus = $options.pauseOnFocus
                    ? $options.pauseOnFocus
                    : false,
                $asNavFor = $options.asNavFor ? $options.asNavFor : '',
                $fade = $options.fade ? $options.fade : false,
                $autoplay = $options.autoplay ? $options.autoplay : false,
                $autoplaySpeed = $options.autoplaySpeed
                    ? parseInt($options.autoplaySpeed, 10)
                    : 5000,
                $swipe = $options.swipe ? $options.swipe : true,
                $swipeToSlide = $options.swipeToSlide
                    ? $options.swipeToSlide
                    : true,
                $touchMove = $options.touchMove ? $options.touchMove : false,
                $verticalSwiping = $options.verticalSwiping
                    ? $options.verticalSwiping
                    : true,
                $draggable = $options.draggable ? $options.draggable : true,
                $arrows = $options.arrows ? $options.arrows : false,
                $dots = $options.dots ? $options.dots : false,
                $adaptiveHeight = $options.adaptiveHeight
                    ? $options.adaptiveHeight
                    : true,
                $infinite = $options.infinite ? $options.infinite : false,
                $centerMode = $options.centerMode ? $options.centerMode : false,
                $centerPadding = $options.centerPadding
                    ? $options.centerPadding
                    : '',
                $variableWidth = $options.variableWidth
                    ? $options.variableWidth
                    : false,
                $speed = $options.speed ? parseInt($options.speed, 10) : 500,
                $appendArrows = $options.appendArrows
                    ? $options.appendArrows
                    : $this,
                $prevArrow =
                    $arrows === true
                        ? $options.prevArrow
                            ? '<span class="' +
                              $options.prevArrow.buttonClass +
                              '"><i class="' +
                              $options.prevArrow.iconClass +
                              '"></i></span>'
                            : '<button class="tty-slick-text-btn tty-slick-text-prev"><i class="lastudioicon-left-arrow"></i></span>'
                        : '',
                $nextArrow =
                    $arrows === true
                        ? $options.nextArrow
                            ? '<span class="' +
                              $options.nextArrow.buttonClass +
                              '"><i class="' +
                              $options.nextArrow.iconClass +
                              '"></i></span>'
                            : '<button class="tty-slick-text-btn tty-slick-text-next"><i class="lastudioicon-right-arrow"></i></span>'
                        : '',
                $rows = $options.rows ? parseInt($options.rows, 10) : 1,
                $rtl =
                    $options.rtl ||
                    $html.attr('dir="rtl"') ||
                    $body.attr('dir="rtl"')
                        ? true
                        : false,
                $slidesToShow = $options.slidesToShow
                    ? parseInt($options.slidesToShow, 10)
                    : 1,
                $slidesToScroll = $options.slidesToScroll
                    ? parseInt($options.slidesToScroll, 10)
                    : 1;

            /*Responsive Variable, Array & Loops*/
            var $responsiveSetting =
                    typeof $this.data('slick-responsive') !== 'undefined'
                        ? $this.data('slick-responsive')
                        : '',
                $responsiveSettingLength = $responsiveSetting.length,
                $responsiveArray = [];
            for (var i = 0; i < $responsiveSettingLength; i++) {
                $responsiveArray[i] = $responsiveSetting[i];
            }

            // Adding Class to instances
            $this.addClass('slick-carousel-' + index);
            $this
                .parent()
                .find('.slick-dots')
                .addClass('dots-' + index);
            $this
                .parent()
                .find('.slick-btn')
                .addClass('btn-' + index);

            if ($spaceBetween != 0) {
                $this.addClass('slick-gutter-' + $spaceBetween);
            }
            if ($spaceBetween_xl != 0) {
                $this.addClass('slick-gutter-xl-' + $spaceBetween_xl);
            }
            var $slideCount = null;
            $this.on('init', function (event, slick) {
                $this.find('.slick-active').first().addClass('first-active');
                $this.find('.slick-active').last().addClass('last-active');
                $slideCount = slick.slideCount;
                if ($slideCount <= $slidesToShow) {
                    $this.children('.slick-dots').hide();
                }
                var $firstAnimatingElements =
                    $('.slick-slide').find('[data-animation]');
                doAnimations($firstAnimatingElements);
            });

            $this.slick({
                slidesToShow: $slidesToShow,
                slidesToScroll: $slidesToScroll,
                asNavFor: $asNavFor,
                autoplay: $autoplay,
                autoplaySpeed: $autoplaySpeed,
                speed: $speed,
                infinite: $infinite,
                rows: $rows,
                arrows: $arrows,
                dots: $dots,
                adaptiveHeight: $adaptiveHeight,
                vertical: $vertical,
                focusOnSelect: $focusOnSelect,
                pauseOnHover: $pauseOnHover,
                pauseOnFocus: $pauseOnFocus,
                centerMode: $centerMode,
                centerPadding: $centerPadding,
                variableWidth: $variableWidth,
                swipe: $swipe,
                swipeToSlide: $swipeToSlide,
                touchMove: $touchMove,
                draggable: $draggable,
                fade: $fade,
                appendArrows: $appendArrows,
                prevArrow: $prevArrow,
                nextArrow: $nextArrow,
                rtl: $rtl,
                customPaging: function (slider, i) {
                    var thumb = $(slider.$slides[i]).data();
                    var number = i + 1;
                    if (number < 10) {
                        return (
                            '<button type="button" class="dot">' +
                            '0' +
                            number +
                            '</button>'
                        );
                    }
                    return (
                        '<button type="button" class="dot">' +
                        number +
                        '</button>'
                    );
                },
                responsive: $responsiveArray,
            });

            $this.on(
                'beforeChange',
                function (e, slick, currentSlide, nextSlide) {
                    $this
                        .find('.slick-active')
                        .first()
                        .removeClass('first-active');
                    $this
                        .find('.slick-active')
                        .last()
                        .removeClass('last-active');
                    var $animatingElements = $(
                        '.slick-slide[data-slick-index="' + nextSlide + '"]'
                    ).find('[data-animation]');
                    doAnimations($animatingElements);
                }
            );

            function doAnimations(elements) {
                var animationEndEvents =
                    'webkitAnimationEnd mozAnimationEnd MSAnimationEnd oanimationend animationend';
                elements.each(function () {
                    var $el = $(this);
                    var $animationDelay = $el.data('delay');
                    var $animationDuration = $el.data('duration');
                    var $animationType = 'animated ' + $el.data('animation');
                    $el.css({
                        'animation-delay': $animationDelay,
                        'animation-duration': $animationDuration,
                    });
                    $el.addClass($animationType).one(
                        animationEndEvents,
                        function () {
                            $el.removeClass($animationType);
                        }
                    );
                });
            }

            $this.on('afterChange', function (e, slick) {
                $this.find('.slick-active').first().addClass('first-active');
                $this.find('.slick-active').last().addClass('last-active');
            });

            // Updating the sliders in tab
            $('body').on(
                'shown.bs.tab',
                'a[data-bs-toggle="tab"], a[data-bs-toggle="pill"]',
                function (e) {
                    $this.slick('setPosition');
                }
            );
        });
        // Added mousewheel for specific slider
        $('.single-blog_slider, .mousewheel-slider').on('wheel', function (e) {
            e.preventDefault();

            if (e.originalEvent.deltaY < 0) {
                $(this).slick('slickNext');
            } else {
                $(this).slick('slickPrev');
            }
        });
    }

    /*----------------------------------------*/
    /*  Offcanvas Inner Nav
/*----------------------------------------*/
    $(
        '.offcanvas-inner_nav li.has-sub > a, .frequently-item li.has-sub a, .pd-tab_item li.has-sub a'
    ).on('click', function () {
        $(this).removeAttr('href');
        var element = $(this).parent('li');
        if (element.hasClass('open')) {
            element.removeClass('open');
            element.find('li').removeClass('open');
            element.find('ul').slideUp();
        } else {
            element.addClass('open');
            element.children('ul').slideDown();
            element.siblings('li').children('ul').slideUp();
            element.siblings('li').removeClass('open');
            element.siblings('li').find('li').removeClass('open');
            element.siblings('li').find('ul').slideUp();
        }
    });

    /*--------------------------
		jQuery Zoom
	---------------------------- */
    $('.zoom').zoom();

    /*--------------------------------
    Price Slider Active
-------------------------------- */
    var sliderrange = $('#slider-range');
    var amountprice = $('#amount');
    $(function () {
        sliderrange.slider({
            range: true,
            min: 20,
            max: 100,
            values: [0, 100],
            slide: function (event, ui) {
                amountprice.val('$' + ui.values[0] + ' - $' + ui.values[1]);
            },
        });
        amountprice.val(
            '$' +
                sliderrange.slider('values', 0) +
                ' - $' +
                sliderrange.slider('values', 1)
        );
    });

    /*--------------------------------
    Scroll To Top
-------------------------------- */
    function scrollToTop() {
        var $scrollUp = $('.scroll-to-top'),
            $lastScrollTop = 0,
            $window = $(window);

        $window.on('scroll', function () {
            var topPos = $(this).scrollTop();
            if (topPos > $lastScrollTop) {
                $scrollUp.removeClass('show');
            } else {
                if ($window.scrollTop() > 200) {
                    $scrollUp.addClass('show');
                } else {
                    $scrollUp.removeClass('show');
                }
            }
            $lastScrollTop = topPos;
        });

        $scrollUp.on('click', function (evt) {
            $('html, body').animate(
                {
                    scrollTop: 0,
                },
                600
            );
            evt.preventDefault();
        });
    }

    scrollToTop();

    /*------------------------------------
	    DateCountdown
	    ------------------------------------- */
    $('.DateCountdown').TimeCircles({
        direction: 'Counter-clockwise',
        fg_width: 0.009,
        bg_width: 0,
        use_background: false,
        animation: 'thick',
        time: {
            Days: {
                text: 'Days',
                color: '#fff',
            },
            Hours: {
                text: 'Hours',
                color: '#fff',
            },
            Minutes: {
                text: 'Mins',
                color: '#fff',
            },
            Seconds: {
                text: 'Secs',
                color: '#fff',
            },
        },
    });

    /*------------------------------------
	    Parallax
	    ------------------------------------- */
    !(function () {
        $('.parallax').jarallax({
            speed: 1.1,
        });
    })();

    /*------------------------------------
	    Magnific Popup
	    ------------------------------------- */
    $('.popup-vimeo').magnificPopup({
        type: 'iframe',
        disableOn: function () {
            if ($(window).width() < 600) {
                return false;
            }
            return true;
        },
    });
    /*------------------------------------
	    Mousemove Animation
	    ------------------------------------- */
    var windowWidth = $(window).width();
    $('.mousemove-wrap').mousemove(function (event) {
        var moveX = ($(window).width() / 2 - event.pageX) * 0.04;
        $('.page-back, .page-back img').css('margin-left', moveX + 'px');
    });
    $('.mousemove-wrap-2').mousemove(function (event) {
        var moveX = ($(window).width() / 2 - event.pageX) * 0.02;
        $('.page-back .circle-img').css('margin-left', moveX + 'px');
    });

    /*------------------------------------
	    Svg Icon
		------------------------------------- */
    document.addEventListener('DOMContentLoaded', function () {
        var icon1 = document.querySelectorAll('.icon1');
        var icon2 = document.querySelectorAll('.icon2');
        var icon3 = document.querySelectorAll('.icon3');
        var icon4 = document.querySelectorAll('.icon4');
        var icon5 = document.querySelectorAll('.icon5');
        var icon6 = document.querySelectorAll('.icon6');
        var icon7 = document.querySelectorAll('.icon7');
        var icon8 = document.querySelectorAll('.icon8');
        var icon9 = document.querySelectorAll('.icon9');
        var icon10 = document.querySelectorAll('.icon10');

        //icon 1
        for (i = 0; i < icon1.length; ++i) {
            icon1[i].innerHTML =
                '<svg class="yena-svg" xmlns="http://www.w3.org/2000/svg" width="62" height="45" viewBox="0 0 62 45"><g fill="currentColor" fill-rule="evenodd"><path d="M21 38a2 2 0 11-4 0 2 2 0 014 0m29 0a2 2 0 11-4 0 2 2 0 014 0"></path><path d="M19 33.19A4.816 4.816 0 0014.19 38 4.816 4.816 0 0019 42.81 4.816 4.816 0 0023.81 38 4.816 4.816 0 0019 33.19M19 45c-3.86 0-7-3.14-7-7s3.14-7 7-7 7 3.14 7 7-3.14 7-7 7"></path><path d="M38 37H24.315v-2.145h11.544V2.145H2.14v32.71h11.544V37H0V0h38zm11-3.81A4.816 4.816 0 0044.19 38 4.816 4.816 0 0049 42.81 4.816 4.816 0 0053.81 38 4.816 4.816 0 0049 33.19M49 45c-3.86 0-7-3.14-7-7s3.14-7 7-7 7 3.14 7 7-3.14 7-7 7"></path><path d="M62 37h-7.607v-2.154h5.47V22.835l-8.578-12.681H38.137v24.692h5.465V37H36V8h16.415L62 22.17z"></path><path d="M42.147 19.932h10.792l-4.15-5.864h-6.642v5.864zM57 22H40V12h9.924L57 22z"></path></g></svg>';
        }
        //icon 2
        for (i = 0; i < icon2.length; ++i) {
            icon2[i].innerHTML =
                '<svg class="yena-svg" xmlns="http://www.w3.org/2000/svg" width="64" height="45" viewBox="0 0 64 45"><g fill="currentColor" fill-rule="evenodd"><path d="M35.187 21.833a1.5 1.5 0 11-1.374-2.667 1.5 1.5 0 011.374 2.667"></path><path d="M2.791 26.888l7.803 15.294 26.045-13.545 3.644-11.57-11.446-3.725L2.791 26.888zM9.701 45L0 25.986l28.653-14.902 14.23 4.63-4.53 14.385L9.7 44.999z"></path><path d="M14.732 32.16c.173.351.262.694.268 1.027a2.24 2.24 0 01-.183.94c-.126.293-.31.561-.553.805a3.59 3.59 0 01-.854.63 3.788 3.788 0 01-1.213.408c-.171.025-.32.035-.446.028a1.121 1.121 0 01-.286-.042.413.413 0 01-.188-.145 1.958 1.958 0 01-.207-.35 3.17 3.17 0 01-.122-.275.914.914 0 01-.054-.192.228.228 0 01.012-.127.167.167 0 01.073-.076c.046-.025.125-.031.237-.02a3.129 3.129 0 00.982-.051c.21-.041.437-.127.678-.256a1.66 1.66 0 00.395-.29c.106-.107.184-.22.236-.34a.84.84 0 00.068-.377 1.004 1.004 0 00-.107-.394.69.69 0 00-.31-.327 1.304 1.304 0 00-.452-.123 3.465 3.465 0 00-.55-.005 21.93 21.93 0 01-.615.034 4.85 4.85 0 01-.638-.012 2.207 2.207 0 01-.62-.144 1.898 1.898 0 01-.564-.355 2.106 2.106 0 01-.473-.655A2.225 2.225 0 019 30.54a2.025 2.025 0 01.162-.853c.114-.265.283-.507.506-.727a3.368 3.368 0 011.247-.778 3.32 3.32 0 01.473-.13 2.57 2.57 0 01.42-.05.878.878 0 01.267.02c.05.017.086.035.11.052a.458.458 0 01.076.08c.028.035.058.082.092.14a5.048 5.048 0 01.233.48c.029.072.049.133.06.185.01.05.01.093-.002.124a.14.14 0 01-.071.078c-.036.02-.106.027-.209.021a4.43 4.43 0 00-.37 0 3.052 3.052 0 00-.476.06 1.959 1.959 0 00-.534.2c-.142.076-.256.16-.344.254a.902.902 0 00-.19.292.697.697 0 00-.046.316c.01.108.04.212.089.312a.69.69 0 00.306.323c.13.067.282.108.454.121.171.015.358.015.56 0 .2-.015.407-.027.62-.036a5.47 5.47 0 01.643.01c.216.017.425.063.626.14.2.078.39.194.566.35.177.155.331.368.464.637m1.619-5.399l-.005.002.498 3.497 1.824-1.027-2.317-2.472zm5.38 3.49c.1.107.175.196.22.267.046.07.06.135.041.193-.018.06-.072.119-.16.18a5.01 5.01 0 01-.376.23 8.64 8.64 0 01-.4.213 1.014 1.014 0 01-.231.089c-.057.011-.103.009-.136-.01a.375.375 0 01-.104-.085l-1.097-1.17-2.415 1.36.24 1.602a.54.54 0 01.008.158.274.274 0 01-.066.14.856.856 0 01-.184.155 5.086 5.086 0 01-.706.39c-.091.039-.163.046-.215.023-.053-.023-.093-.075-.119-.158a2.09 2.09 0 01-.068-.346l-.956-7.347a.658.658 0 010-.188.308.308 0 01.085-.158c.048-.052.123-.11.223-.173a12.97 12.97 0 01.874-.493c.119-.059.215-.098.29-.114a.265.265 0 01.18.012.557.557 0 01.15.121l4.922 5.109zm5.09-2.518c.054.101.096.189.123.262a.85.85 0 01.053.192.239.239 0 01-.013.131.158.158 0 01-.075.077l-3.098 1.546a.499.499 0 01-.343.045c-.113-.026-.209-.114-.288-.263l-3.162-5.947a.157.157 0 01-.014-.108.26.26 0 01.077-.122c.043-.043.107-.091.19-.146a3.54 3.54 0 01.324-.18c.136-.068.25-.119.342-.152.093-.034.17-.055.23-.064a.274.274 0 01.148.01c.037.015.065.04.082.073l2.801 5.27 2.127-1.061a.175.175 0 01.106-.018.235.235 0 01.114.059.79.79 0 01.128.147c.046.065.095.148.148.249m5.02-3.308c.05.107.089.198.113.274.026.075.04.14.045.193a.266.266 0 01-.018.132.165.165 0 01-.069.077l-3.288 1.835a.436.436 0 01-.332.05c-.11-.03-.202-.124-.279-.286l-2.94-6.182c-.076-.162-.092-.298-.05-.412a.49.49 0 01.23-.263l3.267-1.824a.142.142 0 01.094-.018.209.209 0 01.106.061c.04.036.08.088.122.155.042.066.09.155.142.264.048.103.085.192.11.268.026.076.04.14.044.193a.287.287 0 01-.014.13.147.147 0 01-.067.075l-2.338 1.305.824 1.732 1.978-1.104c.03-.016.063-.022.098-.016.035.006.07.026.108.058a.705.705 0 01.118.148c.042.067.088.151.136.254.05.106.089.196.113.27a.778.778 0 01.042.188.243.243 0 01-.021.126.167.167 0 01-.07.074l-1.979 1.104.952 2 2.357-1.315a.143.143 0 01.098-.016.228.228 0 01.11.06.8.8 0 01.12.153c.042.066.088.151.138.257m9.228-3.553l-.007-2.1c7.366-.027 12.824-.787 15.37-2.14 2.43-1.293 4.093-3.09 4.81-5.195.618-1.816.494-3.746-.348-5.433-1.566-3.142-5.668-5.24-10.972-2.42C44.477 6.481 36.11 20.11 36.026 20.248l-1.72-1.12c.354-.581 8.748-14.252 14.685-17.41 6.254-3.325 11.632-.845 13.712 3.325 1.1 2.206 1.263 4.724.457 7.091-.892 2.622-2.897 4.823-5.797 6.366-3.622 1.925-10.86 2.353-16.294 2.373"></path></g></svg>';
        }
        //icon 3
        for (i = 0; i < icon3.length; ++i) {
            icon3[i].innerHTML =
                '<svg class="yena-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 45" width="48" height="45"><g fill="currentColor" fill-rule="evenodd"><path d="M16 29.188c0 .146-.006.272-.017.376-.012.103-.03.188-.052.254a.293.293 0 01-.09.14.2.2 0 01-.124.042h-5.143a.998.998 0 01-.263-.03.336.336 0 01-.18-.118.58.58 0 01-.1-.254 2.449 2.449 0 01-.031-.433c0-.167.007-.31.02-.429a1.308 1.308 0 01.219-.593c.057-.088.132-.185.224-.292l1.549-1.822c.308-.354.557-.677.746-.968.189-.291.337-.557.443-.797a2.966 2.966 0 00.276-1.242c0-.167-.024-.325-.073-.475a1.148 1.148 0 00-.214-.39.978.978 0 00-.356-.263 1.236 1.236 0 00-.504-.094c-.272 0-.513.037-.723.113-.21.076-.394.161-.553.255a4.48 4.48 0 00-.397.258c-.106.079-.19.118-.25.118a.143.143 0 01-.106-.046.333.333 0 01-.072-.152 1.878 1.878 0 01-.046-.284 4.688 4.688 0 01-.007-.73c.007-.078.017-.146.032-.204a.643.643 0 01.055-.152.782.782 0 01.121-.156 1.65 1.65 0 01.318-.232c.154-.093.344-.184.57-.273a5.03 5.03 0 01.747-.224c.271-.06.555-.091.85-.091.465 0 .872.064 1.22.194.347.129.637.309.867.539.23.23.402.504.515.82.113.317.17.657.17 1.021 0 .319-.028.633-.083.941-.056.31-.171.642-.346 1a8.003 8.003 0 01-.74 1.183c-.318.433-.74.936-1.264 1.508l-1.044 1.177h3.525c.046 0 .088.015.127.045.04.03.073.078.101.14a.954.954 0 01.062.252c.014.103.021.226.021.368m6.032-7.45h-.014l-2.487 4.556h2.501v-4.556zM25 27.106c0 .26-.026.458-.077.593-.05.135-.12.203-.207.203h-.839v1.792c0 .05-.015.096-.044.134a.323.323 0 01-.153.096 1.329 1.329 0 01-.284.057 4.563 4.563 0 01-.453.019c-.174 0-.321-.007-.44-.02a1.264 1.264 0 01-.285-.056.296.296 0 01-.146-.096.226.226 0 01-.04-.134v-1.792h-3.61a.563.563 0 01-.181-.027.25.25 0 01-.135-.122.8.8 0 01-.08-.276 3.53 3.53 0 01-.026-.478c0-.164.004-.305.01-.426.008-.12.02-.228.037-.325a1.64 1.64 0 01.073-.276 3.05 3.05 0 01.12-.276l2.932-5.429a.304.304 0 01.124-.118.893.893 0 01.244-.084c.104-.023.237-.04.398-.05.16-.01.355-.015.583-.015.248 0 .46.006.634.019a2.3 2.3 0 01.42.061.616.616 0 01.23.103c.048.041.072.09.072.146v5.965h.839c.077 0 .144.063.2.187.056.126.084.333.084.625zm1.756 5.55a.48.48 0 01-.092.164.414.414 0 01-.159.102 1.147 1.147 0 01-.254.058 2.94 2.94 0 01-.386.02c-.192 0-.35-.01-.473-.032a.755.755 0 01-.279-.093.227.227 0 01-.11-.16.52.52 0 01.029-.231l4.226-13.132a.43.43 0 01.084-.168.385.385 0 01.156-.105c.065-.027.152-.046.258-.06.106-.013.234-.019.385-.019.198 0 .357.01.477.032.12.02.21.051.272.093a.23.23 0 01.106.16.58.58 0 01-.021.231l-4.219 13.14zM39 20.854a4.7 4.7 0 01-.014.388c-.009.11-.021.213-.037.308a1.912 1.912 0 01-.066.27 5.804 5.804 0 01-.096.272l-2.924 7.593a.464.464 0 01-.107.161.44.44 0 01-.182.097 1.426 1.426 0 01-.298.045 7.138 7.138 0 01-.45.012c-.242 0-.434-.009-.576-.027a.869.869 0 01-.313-.084c-.066-.039-.102-.088-.106-.147a.49.49 0 01.048-.219l3.144-7.77h-3.734c-.097 0-.169-.07-.217-.21-.047-.142-.072-.367-.072-.674 0-.154.007-.286.02-.396.015-.11.034-.201.059-.273a.371.371 0 01.09-.154.172.172 0 01.12-.046h5.279c.082 0 .15.009.206.027a.229.229 0 01.13.119.844.844 0 01.072.261c.016.113.024.262.024.447M30.323 43L30 40.921c5.614-.946 10.552-4.655 13.211-9.921l1.789.98c-2.953 5.85-8.44 9.969-14.677 11.02M5.297 18.67l-2.124-.34C4.848 7.708 13.802 0 24.464 0c10.668 0 19.622 7.709 21.291 18.33l-2.123.34C42.13 9.11 34.068 2.171 24.464 2.171c-9.599 0-17.66 6.94-19.167 16.5"></path><path d="M2.054 29.84h2.892V19.16H2.054v10.68zM0 32h7V17H0v15zm43.054-2.16h2.892V19.16h-2.892v10.68zM41 32h7V17h-7v15zM23.207 42.915h4.586v-1.83h-4.586v1.83zM21 45h9v-6h-9v6z"></path></g></svg>';
        }
        //icon 4
        for (i = 0; i < icon4.length; ++i) {
            icon4[i].innerHTML =
                '<svg class="yena-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 42 45" width="42" height="45"><g fill="currentColor" fill-rule="evenodd"><path d="M20.362 28l-5.181-7.532a1.025 1.025 0 01.277-1.435 1.053 1.053 0 011.453.274l3.451 5.017 4.726-6.871a1.054 1.054 0 011.454-.274c.477.32.602.962.277 1.435L20.362 28z"></path><path d="M3.758 2.917C2.732 6.475 2.21 10.275 2.21 14.213c0 13.8 15.358 25.708 18.437 27.956l.161.117.161-.117C24.047 39.92 39.4 28.012 39.4 14.213c0-3.925-.52-7.726-1.549-11.295l-.085-.298-4.154 1.706c-1.265.52-2.604.783-3.982.783-1.377 0-2.717-.263-3.982-.783l-4.842-1.99-4.843 1.99a10.42 10.42 0 01-3.981.783c-1.378 0-2.718-.263-3.983-.783L3.844 2.62l-.086.298zm16.443 41.678C19.376 44.042 0 30.887 0 14.213 0 9.843.609 5.635 1.81 1.7A1.97 1.97 0 014.444.44l4.381 1.8a8.269 8.269 0 003.157.62c1.09 0 2.151-.208 3.155-.62L20.064.215a1.955 1.955 0 011.483-.001l4.927 2.026a8.268 8.268 0 003.156.62 8.264 8.264 0 003.155-.62l4.382-1.8A1.97 1.97 0 0139.8 1.703c1.201 3.945 1.81 8.154 1.81 12.51 0 16.68-19.372 29.83-20.196 30.381l-.607.406-.607-.405z"></path></g></svg>';
        }
        //icon 5
        for (i = 0; i < icon5.length; ++i) {
            icon5[i].innerHTML =
                '<svg class="yena-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 69 92" width="69" height="92"><g fill="currentColor" fill-rule="evenodd"><path d="M45.75 87.115h18.5v-29.21h-18.5v29.21zm3.91-34.095h10.68V30.178H49.66V53.02zm2.334-43.173c.594-1.044 2.454-3.783 6.012-4.676v20.123h-6.012V9.847zM66.625 53.02h-1.534V27.736c0-1.335-1.042-2.418-2.335-2.44V2.442C62.756 1.093 61.693 0 60.381 0 51.223 0 47.608 7.889 47.46 8.225a2.5 2.5 0 00-.215 1.016v16.055c-1.293.022-2.334 1.105-2.334 2.44V53.02h-1.535c-1.312 0-2.375 1.094-2.375 2.443v34.094C41 90.907 42.063 92 43.375 92h23.25C67.937 92 69 90.906 69 89.557V55.463c0-1.35-1.063-2.443-2.375-2.443z"></path><path d="M59 84c1.104 0 2-1.036 2-2.314V63.314C61 62.036 60.104 61 59 61c-1.105 0-2 1.036-2 2.314v18.372c0 1.278.895 2.314 2 2.314M4.75 87.15h18.5V62.446H4.75V87.15zm4.619-29.554h9.262V53.85H9.37v3.746zm16.256 0h-2.244v-6.171c0-1.34-1.063-2.425-2.375-2.425H6.994c-1.311 0-2.374 1.085-2.374 2.425v6.171H2.375C1.063 57.596 0 58.681 0 60.021v29.554C0 90.914 1.063 92 2.375 92h23.25C26.937 92 28 90.914 28 89.575V60.02c0-1.34-1.063-2.425-2.375-2.425z"></path></g></svg>';
        }

        //icon 6
        for (i = 0; i < icon6.length; ++i) {
            icon6[i].innerHTML =
                '<svg class="yena-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 101 62" width="101" height="62"><g fill="currentColor" fill-rule="evenodd"><path d="M78.45 51.445a26.254 26.254 0 005.153-15.66 26.25 26.25 0 00-5.153-15.66 44.402 44.402 0 0116.608 15.66 44.406 44.406 0 01-16.608 15.66m-.058-15.66c0 11.553-9.306 20.952-20.745 20.952-11.44 0-20.745-9.4-20.745-20.952 0-11.554 9.306-20.953 20.745-20.953 11.439 0 20.745 9.4 20.745 20.953m-58.94-1.318a2.052 2.052 0 00-.055-.09c-2.775-4.429-5.5-7.767-9.568-10.087 3.332-1.672 7.139-3.954 11.265-6.429 4.647-2.786 9.452-5.667 13.98-7.896 14.548-6.933 31.255-5.935 44.697 2.668 4.037 2.584 7.47 5.7 10.09 9.036a48.89 48.89 0 00-32.213-12.1c-7.069 0-13.894 1.48-20.285 4.397-6.174 2.818-11.624 6.824-16.2 11.907a2.65 2.65 0 00.174 3.716 2.587 2.587 0 003.68-.176 44.144 44.144 0 0111.844-9.31 26.25 26.25 0 00-5.17 15.682 26.249 26.249 0 005.153 15.659A44.4 44.4 0 0119.45 34.467m63.11-26.28A51.512 51.512 0 0059.711.312c-9.206-.863-18.25.786-26.877 4.901l-.03.014c-4.724 2.325-9.628 5.266-14.37 8.109-6.57 3.94-12.776 7.66-16.333 8.367A2.626 2.626 0 000 24.223a2.628 2.628 0 001.98 2.616c5.844 1.46 9.005 3.967 12.988 10.31A49.842 49.842 0 0032.644 55.13 48.892 48.892 0 0057.647 62a48.893 48.893 0 0025.003-6.87 49.846 49.846 0 0017.68-17.987c.228-.383.363-.828.373-1.305v-.061C100.7 25.92 93.75 15.348 82.56 8.187"></path><path d="M57.5 48c2.778 0 5.345-.907 7.42-2.44h-.014a6.152 6.152 0 115.085-9.613c.005-.148.009-.297.009-.447C70 28.597 64.403 23 57.5 23c-2.185 0-4.239.561-6.026 1.547.042-.002.084-.004.125-.004a3.93 3.93 0 11-3.848 3.134A12.45 12.45 0 0045 35.5C45 42.403 50.596 48 57.5 48"></path></g></svg>';
        }

        // icon 7
        for (i = 0; i < icon7.length; ++i) {
            icon7[i].innerHTML =
                '<svg class="yena-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 60 84" width="60" height="84"><g fill="none" fill-rule="evenodd"><path fill="currentColor" d="M29.906 79.24C15.88 79.24 4.47 67.864 4.47 53.883c0-13.98 11.41-25.355 25.436-25.355 14.025 0 25.436 11.375 25.436 25.355S43.93 79.239 29.906 79.239zM27.26 19.107h5.29v5.083a30.426 30.426 0 00-2.645-.117c-.889 0-1.77.04-2.645.117v-5.083zm-4.437-12.17c1.348-.549 3.857-1.342 7.082-1.342 3.22 0 5.73.792 7.081 1.342v7.715H22.824V6.937zm28.228 25.867c-3.931-3.918-8.765-6.61-14.032-7.885v-5.812h2.202a2.23 2.23 0 002.234-2.227V5.529c0-.788-.417-1.517-1.097-1.918-.171-.1-4.265-2.47-10.453-2.47-6.189 0-10.283 2.37-10.453 2.47a2.226 2.226 0 00-1.098 1.918V16.88c0 1.23 1 2.227 2.235 2.227h2.202v5.812c-5.268 1.276-10.102 3.967-14.033 7.885C3.111 38.435 0 45.921 0 53.884c0 7.963 3.11 15.45 8.76 21.08 5.647 5.63 13.158 8.731 21.146 8.731 7.988 0 15.498-3.102 21.146-8.731 5.648-5.63 8.759-13.117 8.759-21.08 0-7.963-3.11-15.449-8.76-21.079z"></path><path fill="currentColor" d="M29.215 34a2.215 2.215 0 000 4.43c9.018 0 16.355 7.337 16.355 16.354a2.215 2.215 0 104.43 0C50 43.324 40.676 34 29.215 34M45.377 6.82c.277 0 .557-.053.828-.162l6.221-2.52c1.108-.45 1.635-1.694 1.178-2.78C53.146.27 51.877-.248 50.769.201l-6.22 2.52c-1.109.449-1.637 1.695-1.179 2.781a2.173 2.173 0 002.007 1.318M45.27 18.23l5.89 2.603c.257.114.522.167.784.167.807 0 1.573-.512 1.9-1.36.433-1.122-.066-2.407-1.115-2.87l-5.89-2.603c-1.048-.463-2.25.07-2.683 1.192-.433 1.123.066 2.408 1.115 2.872M46.038 8C44.913 8 44 9.12 44 10.5s.913 2.5 2.038 2.5h6.925C54.088 13 55 11.88 55 10.5S54.088 8 52.963 8h-6.925z"></path></g></svg>';
        }
        // icon 8
        for (i = 0; i < icon8.length; ++i) {
            icon8[i].innerHTML =
                '<svg class="yena-svg" xmlns="http://www.w3.org/2000/svg" width="78" height="81" viewBox="0 0 78 81"><g fill="none" fill-rule="evenodd"><path fill="currentColor" d="M70.592 76.75h-7.386l-2.788-26.5H73.38l-2.788 26.5zm6.66-30.046A2.068 2.068 0 0075.701 46h-6.716V25.31l4.735-15.244c0-3.838-3.053-6.948-6.82-6.948-3.768 0-6.822 3.11-6.822 6.948l4.735 15.244V46h-6.716a2.07 2.07 0 00-1.551.704 2.15 2.15 0 00-.523 1.647L59.258 79.1c.114 1.08 1.008 1.9 2.074 1.9h11.134c1.066 0 1.96-.82 2.074-1.9l3.235-30.75a2.15 2.15 0 00-.523-1.647zM26.915 76.542h-2.038c-6.33 0-13.02-5.003-14.61-10.924l-.947-3.522h9.387a9.717 9.717 0 007.189 3.14c2.86 0 5.43-1.216 7.189-3.14h9.386l-.945 3.522c-1.591 5.921-8.282 10.924-14.611 10.924zM5.954 38.228c1.47-1.837 3.854-2.848 6.714-2.848h26.455c2.86 0 5.245 1.011 6.715 2.848 1.47 1.836 1.884 4.322 1.165 6.998l-1.236 4.6H33.085a9.718 9.718 0 00-7.19-3.14 9.718 9.718 0 00-7.188 3.14H6.025l-1.236-4.6c-.718-2.676-.305-5.162 1.165-6.998zM21.965 4.322h7.862l2.967 26.766H18.998l2.967-26.766zM35.3 54.118h9.314l-.99 3.686H35.3a8.991 8.991 0 000-3.686zm-14.56 1.843c0-2.748 2.314-4.983 5.156-4.983 2.843 0 5.155 2.235 5.155 4.983 0 2.748-2.312 4.983-5.155 4.983-2.842 0-5.155-2.235-5.155-4.983zM7.178 54.118h9.315a8.964 8.964 0 000 3.686H8.168l-.99-3.686zm31.946-23.03H37.26l-3.23-29.14C33.908.857 32.955.03 31.82.03H19.97c-1.135 0-2.086.827-2.208 1.917l-3.23 29.14h-1.865c-4.265 0-7.896 1.604-10.226 4.515-2.33 2.91-3.022 6.712-1.95 10.702l5.477 20.392c1.018 3.791 3.54 7.345 7.102 10.008 3.561 2.663 7.754 4.13 11.806 4.13h2.038c4.051 0 8.245-1.467 11.806-4.13 3.562-2.663 6.083-6.217 7.102-10.008L51.3 46.304c1.072-3.99.38-7.791-1.95-10.702-2.33-2.91-5.961-4.514-10.227-4.514z"></path></g></svg>';
        }
        // icon 9
        for (i = 0; i < icon9.length; ++i) {
            icon9[i].innerHTML =
                '<svg class="yena-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 35 58" width="35" height="58"><g fill="none" fill-rule="evenodd"><path fill="currentColor" d="M17.477 54.92c-2.602 0-4.54-.436-5.597-.75v-4.915h11.194v4.915c-1.059.314-2.997.75-5.597.75zM5.84 3.102l-.884 4.64h-.673L3.4 3.1h2.442zm21.021 0l-.884 4.64h-3.873l.885-4.64h3.872zm-7.006 0l-.885 4.64h-3.873l.885-4.64h3.873zm-7.007 0l-.885 4.64H8.091l.884-4.64h3.874zm10.49 43.075H11.615L4.87 10.82h25.211L23.34 46.176zm7.33-38.435h-1.557l.885-4.64h1.557l-.885 4.64zM34.601.58a1.539 1.539 0 00-1.186-.559H1.539A1.539 1.539 0 00.027 1.85l8.775 46.011v7.4c0 .605.354 1.155.906 1.404.12.054 3.013 1.335 7.769 1.335 4.755 0 7.648-1.281 7.769-1.335a1.54 1.54 0 00.906-1.404v-7.4l8.775-46.01A1.54 1.54 0 0034.6.58z"></path><path fill="currentColor" d="M24.71 16.027c-.86-.155-1.691.378-1.855 1.192l-2.827 14c-.164.814.4 1.599 1.262 1.754.1.018.2.027.299.027.746 0 1.412-.5 1.556-1.219l2.827-14c.164-.814-.4-1.6-1.262-1.754"></path></g></svg>';
        }
        // icon 10
        for (i = 0; i < icon10.length; ++i) {
            icon10[i].innerHTML =
                '<svg class="yena-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 56 51" width="56" height="51"><g fill="none" fill-rule="evenodd"><path fill="currentColor" d="M45.833 47.998H10.145c-3.445 0-6.33-2.466-7.017-5.742H52.85c-.686 3.276-3.572 5.742-7.017 5.742M6.819 24.558c0-11.788 9.497-21.378 21.17-21.378 11.673 0 21.17 9.59 21.17 21.378 0 5.515-2.053 10.71-5.794 14.695H12.614c-3.742-3.985-5.795-9.18-5.795-14.695m47.673 14.695h-7.236a24.438 24.438 0 004.877-14.695c0-6.512-2.512-12.635-7.072-17.24C40.5 2.713 34.438.178 27.989.178s-12.511 2.535-17.072 7.14c-4.56 4.605-7.071 10.728-7.071 17.24a24.43 24.43 0 004.876 14.695H1.486c-.82 0-1.486.673-1.486 1.502C0 46.405 4.551 51 10.145 51h35.688c5.594 0 10.145-4.596 10.145-10.245 0-.83-.665-1.502-1.486-1.502"></path><path fill="currentColor" d="M40.728 11.37C37.328 7.907 32.808 6 28 6s-9.328 1.907-12.728 5.37C11.872 14.833 10 19.437 10 24.334c0 4.047 1.263 7.877 3.652 11.075a1.453 1.453 0 002.06.285c.647-.5.772-1.44.28-2.099-1.996-2.672-3.05-5.874-3.05-9.261 0-4.097 1.565-7.949 4.41-10.846C20.196 10.591 23.978 8.996 28 8.996c4.022 0 7.804 1.595 10.648 4.492 2.845 2.897 4.411 6.749 4.411 10.846 0 3.387-1.055 6.59-3.051 9.261a1.516 1.516 0 00.28 2.1c.265.205.578.305.889.305a1.46 1.46 0 001.171-.59C44.737 32.21 46 28.38 46 24.333c0-4.897-1.872-9.501-5.272-12.964"></path><path fill="currentColor" d="M23.378 22.592l5.214-5.214a1.393 1.393 0 00-1.97-1.97l-5.214 5.214a1.392 1.392 0 101.97 1.97M34.56 17.44a1.5 1.5 0 00-2.121 0l-11 11a1.5 1.5 0 102.122 2.12l11-11a1.5 1.5 0 000-2.12m-1.182 9.01l-4.93 4.93a1.536 1.536 0 002.172 2.17l4.93-4.929a1.536 1.536 0 00-2.172-2.171"></path></g></svg>';
        }
    });

    var icons = document.querySelectorAll('.svg-icons');

    for (var i = 0; i < icons.length; i++) {
        icons[i].addEventListener(
            'click',
            function () {
                this.classList.toggle('active');
            },
            false
        );
    }

    /*----------------------------------------*/
    /*  Home Slider Five
/*----------------------------------------*/
    var homeSlider = $('.home-slider-5');
    homeSlider.on('init', function (event, slick) {
        mySlideFunc(-1, 1);
    });
    homeSlider.slick({
        infinite: true,
        arrows: true,
        autoplay: true,
        fade: false,
        dots: true,
        autoplaySpeed: 5000,
        speed: 1000,
        lazyLoad: 'progressive',
        pauseOnHover: false,
        pauseOnFocus: false,
        cssEase: 'cubic-bezier(0.87, 0.03, 0.41, 0.9)',
        vertical: true,
        verticalSwiping: true,
        swipe: false,
        slidesToShow: 1,
        slidesToScroll: 1,
        prevArrow:
            '<button class="slick-prev"><i class="lastudioicon-left-arrow"></i></button>',
        nextArrow:
            '<button class="slick-next"><i class="lastudioicon-right-arrow"></i></button>',
    });
    // Slider Navigation Image SRC
    var itemBg = $('.itemBg');
    $('.hero-slider-active .singleSlide').each(function () {
        var itmeImg = $(this).find('.itemBg img').attr('src');
        $(this).css({
            background: 'url(' + itmeImg + ')',
        });
    });

    homeSlider.on(
        'beforeChange',
        function (event, slick, currentSlide, nextSlide) {
            mySlideFunc(currentSlide - 1, nextSlide);
        }
    );

    homeSlider.on(
        'afterChange',
        function (event, slick, currentSlide, nextSlide) {
            mySlideFunc(currentSlide - 1, currentSlide + 1);
        }
    );

    // Next Prev Image Active Botton
    function mySlideFunc(prevSlide, nextSlide) {
        var nextItem = homeSlider.find('[data-slick-index=' + nextSlide + ']');
        var nextImage = nextItem.find('img').attr('src');
        var prevItem = homeSlider.find('[data-slick-index=' + prevSlide + ']');
        var prevImage = prevItem.find('img').attr('src');
        $('.slick-next').css('background-image', 'url(' + nextImage + ')');
        $('.slick-prev').css('background-image', 'url(' + prevImage + ')');
    }

    /*----------------------------------------*/
    /*  Isotope
/*----------------------------------------*/
    if ($('.masonry-grid').elExists()) {
        var $masonryGrid = $('.masonry-grid').isotope({
            itemSelector: '.grid-item',
            percentPosition: true,
            layoutMode: 'masonry',
            masonry: {
                columnWidth: 0,
            },
        });
        $masonryGrid.imagesLoaded().progress(function () {
            $masonryGrid.isotope('layout');
        });
    }
    /*----------------------------------------*/
    /*  Light Gallery
/*----------------------------------------*/
    $('.lightgallery').lightGallery({
        selector: '.gallery-item',
    });

    /*-----------------------
        Shop filter active 
    ------------------------- */
    $('.filter-btn').on('click', function (e) {
        e.preventDefault();
        $('.filter-body').slideToggle();
    });
})(jQuery);
