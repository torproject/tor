## Read data
t <- read.table("exit-capacity.dat", header=TRUE)

## Normalize columns
t[,2] <- t[,2]/max(t[,2])*100
t[,3] <- t[,3]/max(t[,3])*100

## Remove uninteresting ports
ports <- c(22, 25, 80, 119, 135, 443,
           563, 8080, 6667)
t <- t[t$port %in% ports,]

## Plot
pdf("exit-capacity.pdf")
par(las=1)
col <- grey(c(1,4)/5)
barplot(t(as.matrix(t[,2:3])), names=t$port,
        beside=TRUE, xlab="Port number",
        ylab="Exit capacity available (%)",
        col=col, cex.axis=0.8, cex.names=0.8)
par(xpd=TRUE)
legend(x="topright", legend=c("Nodes", "Bandwidth"),
       fill=col, bty="n", inset=c(-0.05,-0.15))
dev.off()
