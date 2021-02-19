var dps_x = eval(`{{chart_x|safe}}`);
var dps_y = eval(`{{chart_y|safe}}`);

var data = [];

for (i=0; i<dps_x.length; i++) {
    data.push({x:dps_x[i], y:dps_y[i]});
}

var widthpx = window.innerWidth-100;//800;
var heightpx = window.innerHeight-100;//600;

var margin = {top: 200, right: 200, bottom: 100, left: 200},
    width  = widthpx - margin.left - margin.right,
    height = heightpx - margin.top - margin.bottom;

var x = d3.scaleLinear()
        .domain(d3.extent(data, function(d) { return d.x;}))
        .range([0, width]);

var y = d3.scaleLinear()
        .domain(d3.extent(data, function(d) { return d.y;}))
        .range([height, 0]);

var line = d3.line()
        .x(function(d, i) { return x(i); })
        .y(function(d, i) { return y(d); });

        // Set the zoom and Pan features: how much you can zoom, on which part, and what to do when there is a zoom
var zoom = d3.zoom()
    .scaleExtent([.5, 2])  // This control how much you can unzoom (x0.5) and zoom (x20)
    .extent([[0, 0], [width, height]])
    .on("zoom", zoomChart);


var svg = d3.select("body").append("svg")
        .attr("width", width + margin.left + margin.right)
        .attr("height", height + margin.top + margin.bottom)
        .append("g")
        .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

        // This add an invisible rect on top of the chart area. This rect can recover pointer events: necessary to understand when the user zoom
svg.append("rect")
    .attr("width", width)
    .attr("height", height)
    .style("fill", "none")
    .style("pointer-events", "all")
    .attr('transform', 'translate(' + margin.left + ',' + margin.top + ')')
    .call(zoom);

svg.append("defs").append("clipPath")
        .attr("id", "clip")
        .append("rect")
        .attr("width", width)
        .attr("height", height);

var xaxis_pos = heightpx - margin.bottom - 200;

var xaxis = svg.append("g")
        .attr("class", "xaxis")
        .attr("transform", "translate(0," + xaxis_pos + ")")
        .style("font", "60px times")
        .call(d3.axisBottom().tickFormat(function(d){return d/1000000 + " Million"}).scale(x))
      
    //     svg.append("text")             
    //   .attr("transform",
    //         "translate(" + (width/2) + " ," + 
    //                        (height - margin.top - 20) + ")")
    //   .style("text-anchor", "middle")
    //   .text("Date");


    //   // text label for the y axis
    //      svg.append("text")
    //      .attr("transform", "rotate(-90)")
    //      .attr("y", 0 - margin.left)
    //      .attr("x",0 - (height / 2))
    //      .attr("dy", "1em")
    //      .style("text-anchor", "middle")
    //      .style("font", "80px times")
    //      .text("Value"); 

var yaxis = svg.append("g")
        .attr("class", "yaxis")
        .style("font", "80px times")
        .call(d3.axisLeft().scale(y));

var radius = 10;

svg.append("g")
    .selectAll("circle")
    .data(data)
    .enter()
    .append("circle")
    .attr("cx", function(d) { return x(d.x)})
    .attr("cy", function(d) { return y(d.y)})
    .attr("r", radius)
    .style("fill","blue")
    .on("mouseover", handleMouseOver)
    .on("mouseout", handleMouseOut)
    .on("click", handleClick)


// Create Event Handlers for mouse
function handleMouseOver(d, i) {  // Add interactivity
    // Use D3 to select element, change color and size
    d3.select(this).style("fill","orange")
        .attr("r", radius*2)

    // Specify where to put label of text
    svg.append("text").attr("id", "t1337")
        .attr("x", x(d.x) - 30)
        .attr("y", y(d.y) - 15)
        .text([d.x, d.y]);
}

function handleMouseOut(d, i) {
    // Use D3 to select element, change color back to normal
    d3.select(this).style("fill", "blue")
        .attr("r", radius)

    // Select text by id and then remove
     d3.select("#t1337").remove();  // Remove text location
//     d3.selectAll("text").remove();
  }


function handleClick(d,i){
    console.log("selected" + d);
    d3.select(this)
        .transition()
        .duration(500)
        .style("fill","red")
        .transition()
        .duration(500)
        .style("fill","blue");
        
    // Specify where to put label of text
    svg.append("text")
        .attr("x", x(d.x) + 30)
        .attr("y", y(d.y) + 15)
        .style("fill","red")
        .text("You've selected " + d.x + " now transition to Ghidra!")
        .transition()
        .duration(5000)
        .transition()
        .duration(5000)
        .remove()
    
    socket.emit('selection', d.x);
}

function zoomChart(){
    console.log("got to zoom chart")
    var newX = d3.event.transform.rescaleX(x);
    var newY = d3.event.transform.rescaleY(y);

    xaxis.call(d3.axisBottom(newX));
    yaxis.call(d3.axisLeft(newY));

    svg.selectAll("circle")
        .attr('cx', function(d) {return newX(d.x)})
        .attr('cy', function(d) {return newY(d.y)});
    x = newX;
    y = newY;
}

var socket = io.connect('http://' + document.domain + ':' + location.port + '/test');
socket.on('addnodes', function(msg) {
    if (typeof msg.list !== "undefined"){
        console.log(msg);
        for (var i in msg.list){
            data.push({
                x: msg.list[i].x,
                y: msg.list[i].y
            });
        }

        x.domain(d3.extent(data, function (d) {return d.x}));
        y.domain(d3.extent(data, function (d) {return d.y}));
        xaxis.transition().call(d3.axisBottom(x).tickFormat(function(d){return d/1000000 + "M"}));
        yaxis.transition().call(d3.axisLeft(y));

        svg.selectAll("circle")
            .data(data)
            .enter()
            .append("circle")
            .attr("cx", function(d) { return x(d.x)})
            .attr("cy", function(d) { return y(d.y)})
            .attr("r", radius)
            .style("fill","blue")
            .on("mouseover", handleMouseOver)
            .on("mouseout", handleMouseOut)
            .on("click", handleClick)


        svg.selectAll("circle")
            .data(data)
            .transition()
            .attr("cx", function (d) {return x(d.x)})
            .attr("cy", function (d) {return y(d.y)})
    }else{
        console.log("Message of undefined format");
    }
});