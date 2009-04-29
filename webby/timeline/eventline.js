var tl;

function fixupSimile() {
  SimileAjax.DateTime.parseNativeDate = function (string) {
    try {
      var date = eval('new ' + string); // string should be 'Date(yy,mm,dd)' or another valid Date constructor
      if (date == undefined) return null;
      return date;
    } catch (e) {
      return null;
    }
  };

  SimileAjax.NativeDateUnit.getParser = function(format) {
    if (typeof format == "string") {
      format = format.toLowerCase();
    }
    if (format == "javascriptnative") {
      return SimileAjax.DateTime.parseNativeDate;
    }
    return (format == "iso8601" || format == "iso 8601") ?
      SimileAjax.DateTime.parseIso8601DateTime :
      SimileAjax.DateTime.parseGregorianDateTime;
  };
}

function onLoad() {
  fixupSimile();

  var eventSource = new Timeline.DefaultEventSource(0);

  var showDate = new Date(1);

  var theme = Timeline.ClassicTheme.create(); // create the theme
  theme.event.bubble.width = 400;

  var bandInfos = [
    Timeline.createBandInfo({
      width:          "60%",
      intervalUnit:   Timeline.DateTime.HOUR,
      intervalPixels: 100,
      eventSource:    eventSource,
      date: showDate,
      theme: theme
    }),
    Timeline.createBandInfo({
      width:          "30%",
      intervalUnit:   Timeline.DateTime.DAY,
      intervalPixels: 400,
      eventSource:    eventSource,
      date: showDate,
      theme: theme
    }),
    Timeline.createBandInfo({
      width:          "10%",
      intervalUnit:   Timeline.DateTime.DAY,
      intervalPixels: 100,
      eventSource:    eventSource,
      showEventText:  false,
      layout: "overview",
      date: showDate,
      theme: theme
    }),
  ];
  bandInfos[1].syncWith = 0;
  bandInfos[1].highlight = true;
  bandInfos[2].syncWith = 0;
  bandInfos[2].highlight = true;

  tl = Timeline.create(document.getElementById("timeline"), bandInfos);
  var filename = "chroni.js?"+ (new Date().getTime());
  tl.loadJSON(filename, function(json, url) {
                eventSource.loadJSON(json, url);
            });

}

var resizeTimerID = null;
function onResize() {
    if (resizeTimerID == null) {
        resizeTimerID = window.setTimeout(function() {
            resizeTimerID = null;
            tl.layout();
        }, 500);
    }
}
