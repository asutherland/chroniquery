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

  var contextSource = new Timeline.DefaultEventSource(0);
  var specificSource = new Timeline.DefaultEventSource(0);


  var showDate = new Date(1);

  var theme = Timeline.ClassicTheme.create(); // create the theme
  theme.event.bubble.width = 400;

  var tsLabeller = {
    n1K: 1000,
    n100K: 100 * 1000,
    n1M: 1000 * 1000,
    n100M: 100 * 1000 * 1000,
    n1G: 1000 * 1000 * 1000,
    n1T: 1000 * 1000 * 1000,

    labelInterval: function(d, intervalUnit) {
      return {
        text: this.labelText(d.valueOf()),
        emphasized: false,
      };
    },
    labelText: function (ts) {
      if (ts < this.n1M)
        return Math.floor(ts / this.n1K) + "K";
      else if (ts < this.n1G)
        return Math.floor(ts / this.n1M) + "M";
      else if (ts < this.ns1T)
        return Math.floor(ts / this.n1G) + "G";
      else
        return Math.floor(ts / this.n1T) + "T";
    },
    labelPrecise: function (d) {
      return this.labelInterval(d);
    },
  };

  var bandInfos = [
    Timeline.createBandInfo({
      width:          "10%",
      intervalUnit:   Timeline.DateTime.HOUR,
      intervalPixels: 400,
      eventSource:    contextSource,
      labeller: tsLabeller,
      date: showDate,
      theme: theme
    }),
    Timeline.createBandInfo({
      width:          "60%",
      intervalUnit:   Timeline.DateTime.HOUR,
      intervalPixels: 400,
      eventSource:    specificSource,
      labeller: tsLabeller,
      date: showDate,
      theme: theme
    }),
    Timeline.createBandInfo({
      width:          "20%",
      intervalUnit:   Timeline.DateTime.DAY,
      intervalPixels: 400,
      eventSource:    specificSource,
      labeller: tsLabeller,
      date: showDate,
      layout: "overview",
      theme: theme
    }),
    Timeline.createBandInfo({
      width:          "10%",
      intervalUnit:   Timeline.DateTime.DAY,
      intervalPixels: 100,
      eventSource:    specificSource,
      showEventText:  false,
      layout: "overview",
      labeller: tsLabeller,
      date: showDate,
      theme: theme
    }),
  ];
  bandInfos[0].labeller = tsLabeller;
  bandInfos[1].labeller = tsLabeller;
  bandInfos[2].labeller = tsLabeller;
  bandInfos[3].labeller = tsLabeller;

  bandInfos[1].syncWith = 0;
  bandInfos[2].syncWith = 0;
  bandInfos[2].highlight = true;
  bandInfos[3].syncWith = 0;
  bandInfos[3].highlight = true;

  tl = Timeline.create(document.getElementById("timeline"), bandInfos);
  var filename = "chroni.js";
  if (window.location.hostname == "localhost")
    filename += "?" + new Date().getTime();
  tl.loadJSON(filename, function(json, url) {
                contextSource.loadJSON(json.context, url);
                specificSource.loadJSON(json.specific, url);
            });

  if (window.location.hash) {
    tl.getBand(0).setMinVisibleDate(new Date(parseInt(window.location.hash.substr(1))));
  }
  else {
    tl.getBand(0).setMinVisibleDate(new Date(0));
  }
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
